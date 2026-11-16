"""Reproducible SEC-01 TLS laboratory, synthetic plaintext with real libsignal.
No public port is opened. All child processes are stopped on completion.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid

def uid():
    return uuid.uuid4().hex

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command {Path(str(args[0])).name} failed: {result.stderr}")
    return result.stdout

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-bin", type=Path, required=True)
    parser.add_argument("--relay-bin", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.client_bin = args.client_bin.resolve()
    args.relay_bin = args.relay_bin.resolve()
    processes = []
    files = []
    with tempfile.TemporaryDirectory(prefix="spora-sec-tls-") as tmp:
        root = Path(tmp)
        ca, key = root / "ca.pem", root / "ca.key"
        cert, server_key = root / "server.pem", root / "server.key"
        run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", ca, "-days", "1", "-subj", "/CN=Spora SEC01 Lab CA"])
        csr = root / "server.csr"
        run([args.openssl, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", server_key, "-out", csr, "-subj", "/CN=localhost"])
        ext = root / "extensions"
        ext.write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n", encoding="ascii")
        run([args.openssl, "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", key, "-CAcreateserial", "-out", cert, "-days", "1", "-extfile", ext])
        relays = []
        def start(relay):
            log = open(root / f"{relay['name']}-{len(processes)}.log", "w", encoding="utf-8")
            files.append(log)
            process = subprocess.Popen([str(args.relay_bin), "serve", "--data-dir", str(relay["path"]), "--listen", f"127.0.0.1:{relay['port']}", "--admin-listen", f"127.0.0.1:{relay['admin']}", "--test-only", "--tls-cert", str(cert), "--tls-key", str(server_key)], stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            processes.append(process)
            relay["process"] = process
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("Relay exited during startup")
                try:
                    with socket.create_connection(("127.0.0.1", relay["port"]), 0.1):
                        return
                except OSError:
                    time.sleep(0.05)
            raise RuntimeError("Relay readiness timeout")

        def client(name, *command):
            output = run([args.client_bin, "--profile", root / name, "--allow-test-key", "--ca", ca, *command])
            return json.loads(output)

        try:
            for i in range(2):
                relay = {"name": f"relay{i}", "path": root / f"relay{i}", "port": port(), "admin": port()}
                run([args.relay_bin, "init", "--data-dir", relay["path"], "--test-only"])
                config = json.loads((relay["path"] / "relay.json").read_text())
                token = root / f"provision{i}.txt"
                token.write_text(config["provisioning_token"], encoding="ascii")
                relay["token"] = token
                relays.append(relay)
                start(relay)
            identities = {}
            for name in ["alice", "bob", "bob2"]:
                identities[name] = client(name, "init")
                for r in relays:
                    client(name, "queue", "--endpoint", f"https://127.0.0.1:{r['port']}", "--provisioning-token-file", r["token"])
            conversation = uid()
            for bob in ["bob", "bob2"]:
                for sender, receiver in [("alice", bob), (bob, "alice")]:
                    path = root / f"{sender}-to-{receiver}.invitation.json"
                    client(sender, "invite", "--request", uid(), "--for-fingerprint", identities[receiver]["fingerprint"], "--output", path)
                    client(receiver, "import", "--invitation", path, "--expected-fingerprint", identities[sender]["fingerprint"], "--conversation", conversation)
            peers = ",".join(identities[b]["device"]["id"] for b in ["bob", "bob2"])
            request = uid()
            message = client("alice", "send", "--request", request, "--peers", peers, "--text", "SEC01 artificial TLS message")
            relays[1]["process"].kill()
            relays[1]["process"].wait()
            assert client("alice", "dispatch") == 2
            assert client("alice", "status")["processed_receipts"] == 0
            start(relays[1])
            time.sleep(3.1)  # Maximum first retry backoff is 3 seconds.
            assert client("alice", "dispatch") == 2
            assert client("alice", "send", "--request", request, "--peers", peers, "--text", "SEC01 artificial TLS message") == message
            for name in ["bob", "bob2"]:
                assert client(name, "fetch") == 2
                assert client(name, "consume") == 2
                assert client(name, "status")["message_count"] == 0
            for relay in relays:
                relay["process"].kill()
                relay["process"].wait()
                start(relay)
            for name in ["bob", "bob2"]:
                assert client(name, "fetch") == 0
                assert client(name, "apply") == 1
                assert client(name, "receipts") == 1
                assert client(name, "dispatch") == 2
            assert client("alice", "fetch") == 4
            assert client("alice", "consume") == 4
            assert client("alice", "apply") == 2
            result = client("alice", "status")
            assert result["processed_receipts"] == 2 and result["quarantined"] == 0
            report = {"scenario": "three client profiles, two independent TLS Relay processes", "transport": "verified private CA, IP SAN 127.0.0.1", "artificial_messages": True, "encryption": result["suite"], "checks": ["recipient offline during send", "one Relay killed during delivery", "retry after restart", "request idempotency", "four independent route envelopes", "local persistence before consume", "both Relays restarted after consume", "apply after server copies removed", "two authenticated processing receipts"], "alice": {k: v for k, v in result.items() if k != "device"}, "external_specialist_review": "PENDING", "public_internet_deployment": False}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
            print(json.dumps(report, indent=2))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
            for log in files:
                log.close()

if __name__ == "__main__":
    main()
