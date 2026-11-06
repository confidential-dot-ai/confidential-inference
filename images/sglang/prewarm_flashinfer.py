#!/usr/bin/env python3
"""Compile FlashInfer's request-time sampling kernels before a worker starts.

The image bakes no JIT cache. Without this step, the first request that needs
FlashInfer sampling (top-k/top-p, min-p, or a batch that mixes greedy and
default sampling) compiles the module inside the scheduler thread; that build
outlasts the pair's progress timeout and the pair is restarted. The kernels
compile into FLASHINFER_WORKSPACE_BASE, which the workers share.

The program uses synthetic tensors only. It prints nothing; the exit status is
the result: 0 when every call returned, 1 when any call failed.
"""
import sys

# DeepSeek-V4.1 vocabulary. The kernels are generic over the row width; the
# real width keeps the warm calls on the same code paths as serving.
VOCAB = 129280
# sglang's TOP_K_ALL ("whole vocabulary"); exercises the unclamped value.
TOP_K_ALL = 1 << 30


def warm() -> None:
    import torch
    import flashinfer
    import flashinfer.sampling as sampling

    device = torch.device("cuda", 0)
    generator = torch.Generator(device=device).manual_seed(0)
    logits = torch.randn(4, VOCAB, device=device, generator=generator)
    probs = torch.softmax(logits, dim=-1)
    top_ks = torch.tensor([1, 40, TOP_K_ALL, VOCAB], dtype=torch.int32, device=device)
    top_ps = torch.tensor([1.0, 0.9, 0.95, 1.0], dtype=torch.float32, device=device)
    min_ps = torch.tensor([0.0, 0.05, 0.1, 0.0], dtype=torch.float32, device=device)

    sampling.top_k_renorm_probs(probs, top_ks)
    sampling.top_p_renorm_probs(probs, top_ps)
    sampling.top_k_top_p_sampling_from_probs(probs, top_ks, top_ps, filter_apply_order="joint")
    sampling.min_p_sampling_from_probs(probs, min_ps)
    flashinfer.top_k(logits, 8)
    torch.cuda.synchronize(device)


def main() -> int:
    try:
        warm()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
