//! Bounded memory for request bodies.
//!
//! The gateway reads a whole request body, parses it as JSON, and can write
//! it again before it sends it to the router. Without a bound, the number of
//! requests in progress times `maximum_body_bytes` sets the memory: 256
//! requests of 32 MiB each would need more than 16 GiB. One budget
//! (`body_memory_bytes`) bounds the memory of all bodies together instead.
//!
//! A request reserves its share of the budget before the gateway reads its
//! body, and keeps part of it until the router sends the response headers:
//!
//! 1. Before the read: `read_cost`, 4 x the `Content-Length` (or 4 x the
//!    limit when the length is not known).
//! 2. After the read: `parse_cost`, the body, the parser's scratch buffer,
//!    and the parsed JSON value. It returns the excess, or takes the
//!    difference at once or gets 429 `body_memory_capacity`: the value of a
//!    body with many small JSON items is larger than the body. A body whose cost is more than the whole budget
//!    gets 413 `request_too_large`.
//! 3. After the gateway drops the parsed value: the size of the body it sends.
//!    For a non-streaming request the router sends its headers only at the
//!    end, so this part stays for the whole request.
//!
//! `docs/request-body-limit.md` has the measured memory of each body shape
//! against `parse_cost`, and the sizing rules.

use std::{sync::Arc, time::Duration};

use axum::body::{Body, Bytes};
use futures_util::StreamExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The budget counts in units of this many bytes, so that a `u32` permit
/// count covers every allowed budget.
const UNIT: usize = 1_024;

/// The smallest `body_memory_bytes`, in multiples of the body limit: one
/// request of the largest size must fit, also with the structure of an agent
/// transcript (about 4.5 x its body in `parse_cost`).
pub const MINIMUM_BUDGET_BODIES: usize = 5;

/// A fixed part of each reservation for small allocations.
const MARGIN: usize = 64 * 1_024;

/// The largest `body_memory_bytes` a deployment can configure: 1 TiB.
pub const MAXIMUM_BODY_MEMORY_BYTES: usize = 1 << 40;

/// The bytes one JSON item (a key or a value) can add to the parsed value,
/// more than its text: the 32-byte `Value` in its parent's vector (at most
/// twice that after vector growth), or a map entry, and the allocator's
/// overhead for its own allocation. Measured: 32 bytes for each array item,
/// about 53 for each key of a large object.
const ITEM_BYTES: usize = 96;

/// The bytes one JSON object can add: a `BTreeMap` leaf node holds 11 entries
/// of a `String` key and a `Value` (about 640 bytes), allocated even for one
/// entry.
const OBJECT_BYTES: usize = 768;

/// The counts that set the size of the parsed value of a JSON text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Shape {
    /// Keys and values: each starts after `[`, `{`, `,`, or `:`, or is the
    /// root value. This counts an empty array or object as one item too.
    pub items: usize,
    /// Objects (`{`).
    pub objects: usize,
    /// The most decoded bytes of one string with an escape. The parser
    /// decodes such a string into a scratch buffer first, which can grow to
    /// twice that.
    pub longest_escaped: usize,
}

/// Count the items and objects of a JSON text outside its strings, and find
/// its longest string with an escape. The text does not need to be valid
/// JSON; the count is then an estimate only, and the parser rejects the text.
#[must_use]
pub fn shape(body: &[u8]) -> Shape {
    let mut shape = Shape {
        items: 1,
        ..Shape::default()
    };
    let mut in_string = false;
    let mut escaped = false;
    // The current string: its raw bytes, the bytes its escapes save, and
    // whether it has an escape.
    let mut raw = 0usize;
    let mut saved = 0usize;
    let mut has_escape = false;
    for &byte in body {
        if in_string {
            raw += 1;
            if escaped {
                escaped = false;
                // `\uXXXX` decodes to at most 3 bytes of its 6 (a surrogate
                // pair to 4 of 12); every other escape to 1 byte of 2.
                saved += if byte == b'u' { 3 } else { 1 };
            } else if byte == b'\\' {
                escaped = true;
                has_escape = true;
            } else if byte == b'"' {
                in_string = false;
                if has_escape {
                    shape.longest_escaped = shape.longest_escaped.max(raw.saturating_sub(saved));
                }
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                raw = 0;
                saved = 0;
                has_escape = false;
            }
            b'{' => {
                shape.objects += 1;
                shape.items += 1;
            }
            b'[' | b',' | b':' => shape.items += 1,
            _ => {}
        }
    }
    shape
}

/// The most memory a request of `length` body bytes with this shape uses
/// while the gateway parses and rewrites it.
#[must_use]
pub fn parse_cost(length: usize, shape: Shape) -> usize {
    // The parsed strings are at most the text, and the gateway drops the
    // read body before it writes the new one: body + value, or value + new
    // body, at most 2 x the text plus the item overhead. During the parse
    // the scratch buffer of escaped strings comes on top.
    length
        .saturating_mul(2)
        .saturating_add(shape.longest_escaped.saturating_mul(2))
        .saturating_add(shape.items.saturating_mul(ITEM_BYTES))
        .saturating_add(shape.objects.saturating_mul(OBJECT_BYTES))
        .saturating_add(MARGIN)
}

/// The reservation before the read: `parse_cost` of a body of one long
/// escaped string (source code: about 3.8 x the body; plain text 2 x; JSON
/// escapes of non-ASCII text 3 x). A body that needs more takes the
/// difference after the read, without a wait.
#[must_use]
pub fn read_cost(declared_or_limit: usize) -> usize {
    declared_or_limit.saturating_mul(4).saturating_add(MARGIN)
}

/// The smallest budget for a body limit (`MINIMUM_BUDGET_BODIES`).
#[must_use]
pub fn minimum_budget(maximum_body_bytes: usize) -> usize {
    maximum_body_bytes
        .saturating_mul(MINIMUM_BUDGET_BODIES)
        .saturating_add(MARGIN)
}

fn units(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(UNIT)).unwrap_or(u32::MAX)
}

/// The shared memory budget of request bodies.
#[derive(Clone)]
pub struct BodyMemory {
    budget: usize,
    units: Arc<Semaphore>,
}

/// Why a reservation failed.
#[derive(Debug, Eq, PartialEq)]
pub enum ReserveError {
    /// The request alone is larger than the whole budget.
    TooLarge,
    /// Other requests hold the budget now.
    Busy,
}

/// One request's share of the body budget. Dropping it returns the share.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<Semaphore>,
    permit: OwnedSemaphorePermit,
}

impl BodyMemory {
    #[must_use]
    pub fn new(budget: usize) -> Self {
        let budget = budget.min(MAXIMUM_BODY_MEMORY_BYTES);
        Self {
            budget,
            units: Arc::new(Semaphore::new(units(budget) as usize)),
        }
    }

    /// The configured budget in bytes.
    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// The bytes no request holds now.
    #[must_use]
    pub fn available(&self) -> usize {
        self.units.available_permits().saturating_mul(UNIT)
    }

    /// Reserve `bytes`, and wait up to `wait` for other requests to return
    /// their share.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` when `bytes` is more than the whole budget, and
    /// `Busy` when the wait ends first.
    pub async fn reserve(&self, bytes: usize, wait: Duration) -> Result<Reservation, ReserveError> {
        if bytes > self.budget {
            return Err(ReserveError::TooLarge);
        }
        let permit =
            tokio::time::timeout(wait, self.units.clone().acquire_many_owned(units(bytes)))
                .await
                .map_err(|_| ReserveError::Busy)?
                .map_err(|_| ReserveError::Busy)?;
        Ok(Reservation {
            budget: self.units.clone(),
            permit,
        })
    }
}

impl Reservation {
    /// The bytes this reservation holds.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.permit.num_permits().saturating_mul(UNIT)
    }

    /// Hold exactly `bytes` (rounded up to the unit): return the excess at
    /// once, or take the difference without a wait.
    ///
    /// # Errors
    ///
    /// Returns `Busy` when the budget does not have the difference now. The
    /// reservation does not change then.
    pub fn resize(&mut self, bytes: usize, budget: &BodyMemory) -> Result<(), ReserveError> {
        if bytes > budget.budget {
            return Err(ReserveError::TooLarge);
        }
        let wanted = units(bytes) as usize;
        let held = self.permit.num_permits();
        if wanted < held {
            drop(self.permit.split(held - wanted));
        } else if wanted > held {
            let extra = u32::try_from(wanted - held).map_err(|_| ReserveError::TooLarge)?;
            let more = self
                .budget
                .clone()
                .try_acquire_many_owned(extra)
                .map_err(|_| ReserveError::Busy)?;
            self.permit.merge(more);
        }
        Ok(())
    }
}

/// Why a body read failed.
#[derive(Debug, Eq, PartialEq)]
pub enum ReadError {
    /// The body is larger than the limit, or than the gateway's ceiling.
    TooLarge,
    /// The client stopped, or the connection failed.
    Failed,
}

fn stream_error(error: &axum::Error) -> ReadError {
    // The ceiling layer (`MAXIMUM_BODY_BYTES_CEILING`) ends a longer body
    // with this error.
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if current.is::<http_body_util::LengthLimitError>() {
            return ReadError::TooLarge;
        }
        source = current.source();
    }
    ReadError::Failed
}

/// Read a whole body of at most `limit` bytes. With a declared length the
/// buffer has that size from the start, so the read never holds two copies.
///
/// # Errors
///
/// Returns `TooLarge` above the limit, and `Failed` when the body stream
/// fails.
pub async fn read(body: Body, declared: Option<usize>, limit: usize) -> Result<Bytes, ReadError> {
    if declared.is_some_and(|length| length > limit) {
        return Err(ReadError::TooLarge);
    }
    let mut stream = body.into_data_stream();
    let Some(declared) = declared else {
        // No declared length: keep the chunks, and copy them into one buffer
        // of the exact size at the end (at most 2 x the body at one time).
        let mut chunks = Vec::new();
        let mut total = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| stream_error(&error))?;
            total = total.saturating_add(chunk.len());
            if total > limit {
                return Err(ReadError::TooLarge);
            }
            chunks.push(chunk);
        }
        return Ok(match chunks.len() {
            0 => Bytes::new(),
            1 => chunks.pop().unwrap_or_default(),
            _ => {
                let mut buffer = Vec::with_capacity(total);
                for chunk in chunks.drain(..) {
                    buffer.extend_from_slice(&chunk);
                }
                Bytes::from(buffer)
            }
        });
    };
    let mut buffer = Vec::with_capacity(declared);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| stream_error(&error))?;
        // HTTP framing makes the body exactly its declared length; the check
        // still bounds the buffer if a sender lies.
        if buffer.len().saturating_add(chunk.len()) > declared {
            return Err(if buffer.len().saturating_add(chunk.len()) > limit {
                ReadError::TooLarge
            } else {
                ReadError::Failed
            });
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_counts_items_outside_strings_only() {
        assert_eq!(
            shape(br#"{"a":[1,2,{"b":"x,y:{["}],"c\"":"\\"}"#),
            Shape {
                items: 10,
                objects: 2,
                // `c\"` and its closing quote, less the 1 byte its escape
                // saves.
                longest_escaped: 3,
            }
        );
        assert_eq!(
            shape(b"\"a long, string: with [ and {\""),
            Shape {
                items: 1,
                objects: 0,
                longest_escaped: 0,
            }
        );
    }

    #[test]
    fn escaped_strings_pay_for_the_scratch_buffer() {
        let code = "fn main() {\n\tprintln!(\"hi\");\n}\n".repeat(1_000);
        let body = serde_json::to_vec(&serde_json::json!({"content": code}))
            .unwrap_or_else(|_| unreachable!());
        let found = shape(&body);
        // The decoded string, not the escaped text.
        assert!(found.longest_escaped <= code.len() + 1, "{found:?}");
        assert!(found.longest_escaped >= code.len());
        assert!(parse_cost(body.len(), found) <= read_cost(body.len()));
        let cjk = "\\u4e2d".repeat(1_000);
        let found = shape(format!(r#"{{"content":"{cjk}"}}"#).as_bytes());
        assert_eq!(found.longest_escaped, 3_001);
    }

    #[test]
    fn the_cost_of_text_is_two_bodies() {
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"user","content":"{}"}}]}}"#,
            "x".repeat(1 << 20)
        );
        let cost = parse_cost(body.len(), shape(body.as_bytes()));
        assert!(cost < body.len() * 2 + 2 * MARGIN, "{cost}");
        assert!(cost <= read_cost(body.len()) + MARGIN);
        assert!(minimum_budget(body.len()) >= cost);
    }

    #[tokio::test]
    async fn reservations_share_one_budget() {
        let memory = BodyMemory::new(4 * UNIT);
        let mut first = memory
            .reserve(3 * UNIT, Duration::from_millis(10))
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            memory
                .reserve(2 * UNIT, Duration::from_millis(10))
                .await
                .err(),
            Some(ReserveError::Busy)
        );
        assert_eq!(
            memory
                .reserve(5 * UNIT, Duration::from_millis(10))
                .await
                .err(),
            Some(ReserveError::TooLarge)
        );
        assert_eq!(first.resize(5 * UNIT, &memory), Err(ReserveError::TooLarge));
        first
            .resize(4 * UNIT, &memory)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(memory.available(), 0);
        first
            .resize(UNIT + 1, &memory)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.bytes(), 2 * UNIT);
        assert_eq!(memory.available(), 2 * UNIT);
        drop(first);
        assert_eq!(memory.available(), 4 * UNIT);
    }

    #[tokio::test]
    async fn a_waiting_reservation_gets_the_returned_share() {
        let memory = BodyMemory::new(2 * UNIT);
        let held = memory
            .reserve(2 * UNIT, Duration::from_millis(10))
            .await
            .unwrap_or_else(|_| unreachable!());
        let waiting = {
            let memory = memory.clone();
            tokio::spawn(async move { memory.reserve(UNIT, Duration::from_secs(5)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(held);
        assert!(waiting.await.unwrap_or_else(|_| unreachable!()).is_ok());
    }

    #[tokio::test]
    async fn read_bounds_the_body_with_and_without_a_declared_length() {
        let body = || Body::from(vec![b'x'; 2_048]);
        assert_eq!(
            read(body(), Some(2_048), 2_048).await.map(|b| b.len()),
            Ok(2_048)
        );
        assert_eq!(read(body(), None, 2_048).await.map(|b| b.len()), Ok(2_048));
        assert_eq!(
            read(body(), Some(2_048), 2_047).await,
            Err(ReadError::TooLarge)
        );
        assert_eq!(read(body(), None, 2_047).await, Err(ReadError::TooLarge));
        // A sender that sends more than it declared.
        assert_eq!(
            read(body(), Some(1_024), 4_096).await,
            Err(ReadError::Failed)
        );
    }
}
