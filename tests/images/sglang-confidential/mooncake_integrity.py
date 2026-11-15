"""Synthetic GPU transfer checks. No model, request or customer data is used."""
import concurrent.futures
import json
import multiprocessing
import os
import resource
import sys

SIZES = [17, 4096, 65536, 1048576]
SIZE = sum(SIZES)


def child(conn, role, mode, ordinal):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.environ['CUDA_VISIBLE_DEVICES'] = '2,3' if role == 'target' else '0,1'
    for key in ('MC_FORCE_TCP', 'MC_INTRANODE_NVLINK', 'SGLANG_MOONCAKE_CUSTOM_MEM_POOL'):
        os.environ.pop(key, None)
    if mode == 'nvlink':
        os.environ['MC_INTRANODE_NVLINK'] = '1'
        os.environ['SGLANG_MOONCAKE_CUSTOM_MEM_POOL'] = 'INTRA_NODE_NVLINK'
    else:
        os.environ['MC_FORCE_TCP'] = '1'
    os.environ['MOONCAKE_PROTOCOL'] = 'tcp'
    import torch
    from sglang.srt.distributed.device_communicators.mooncake_transfer_engine import MooncakeTransferEngine
    torch.cuda.set_device(ordinal)
    allocation = torch.zeros(SIZE + 4096, dtype=torch.uint8, device=f'cuda:{ordinal}')
    offset = 513 if role == 'target' else 257
    data = allocation[offset:offset + SIZE]
    engine = MooncakeTransferEngine('127.0.0.1', gpu_id=ordinal)
    engine.register(data.data_ptr(), SIZE)
    if role == 'target':
        conn.send((engine.session_id, data.data_ptr()))
        for expected in (41, 73):
            assert conn.recv() == 'verify'
            torch.cuda.synchronize()
            conn.send(bool(torch.all(data == expected).item()))
    else:
        session, target = conn.recv()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            data.fill_(41)
            torch.cuda.synchronize()
            result = pool.submit(engine.transfer_sync, session, data.data_ptr(), target, SIZE).result(timeout=30)
            assert result == 0, result
            conn.send('verify')
            assert conn.recv() is True
            data.fill_(73)
            torch.cuda.synchronize()
            offsets, cursor = [], 0
            for size in SIZES:
                offsets.append(cursor)
                cursor += size
            result = pool.submit(engine.batch_transfer_sync, session,
                                 [data.data_ptr() + x for x in offsets],
                                 [target + x for x in offsets], SIZES).result(timeout=30)
            assert result == 0, result
            conn.send('verify')
            assert conn.recv() is True
        conn.send({'mode': mode, 'ordinal': ordinal, 'bytesPerCheck': SIZE,
                   'checks': 2, 'suballocationOffsets': True, 'executorThread': True,
                   'dataEqual': True})
    engine.deregister(data.data_ptr())


def main():
    mode = sys.argv[1]
    context = multiprocessing.get_context('spawn')
    for ordinal in (0, 1):
        target_parent, target_child = context.Pipe()
        sender_parent, sender_child = context.Pipe()
        target = context.Process(target=child, args=(target_child, 'target', mode, ordinal))
        sender = context.Process(target=child, args=(sender_child, 'sender', mode, ordinal))
        target.start()
        # The parent forwards metadata and control messages. It receives no tensor data.
        assert target_parent.poll(40), 'target startup timeout'
        metadata = target_parent.recv()
        sender.start()
        sender_parent.send(metadata)
        for _ in range(2):
            assert sender_parent.poll(40), 'sender timeout'
            assert sender_parent.recv() == 'verify'
            target_parent.send('verify')
            assert target_parent.poll(40), 'verification timeout'
            result = target_parent.recv()
            sender_parent.send(result)
        assert sender_parent.poll(40), 'result timeout'
        print(json.dumps(sender_parent.recv()), flush=True)
        for process in (sender, target):
            process.join(10)
            if process.is_alive():
                process.kill()
                process.join()
            assert process.exitcode == 0, process.exitcode


if __name__ == '__main__':
    main()
