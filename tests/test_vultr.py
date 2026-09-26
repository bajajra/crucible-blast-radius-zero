"""Focused, offline tests for the Vultr inference transport."""

import io
import json
import socket
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from crucible import vultr


class FakeResponse:
    def __init__(self, value):
        self.data = io.BytesIO(json.dumps(value).encode("utf-8"))

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.data.close()

    def read(self, size):
        return self.data.read(size)


class VultrClientTests(unittest.TestCase):
    def test_live_catalog_uses_working_endpoint_without_key(self):
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "secret"}):
            with patch.object(vultr, "_open_request", return_value=FakeResponse({"data": [{"id": "glm-5.3"}]})) as open_url:
                models = vultr.list_models()
        self.assertEqual(models[0]["id"], "glm-5.3")
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.vultrinference.com/v1/models")
        self.assertNotIn("Authorization", request.headers)

    def test_chat_uses_role_override_and_auth_header(self):
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "secret", "VULTR_MODEL_SUPERVISOR": "custom-model"}):
            with patch.object(vultr, "_open_request", return_value=FakeResponse({"choices": [{"message": {"content": "up"}}]})) as open_url:
                text = vultr.chat("supervisor", [{"role": "user", "content": "hello"}], max_tokens=8)
        self.assertEqual(text, "up")
        request = open_url.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.vultrinference.com/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "custom-model")
        self.assertEqual(payload["max_completion_tokens"], 8)
        self.assertEqual(payload["messages"][0]["content"], "hello")

    def test_documented_key_name_is_supported(self):
        with patch.dict("os.environ", {"VULTR_SERVERLESS_INFERENCE_API_KEY": "from-docs", "VULTR_INFERENCE_API_KEY": ""}):
            with patch.object(vultr, "_open_request", return_value=FakeResponse({"choices": [{"message": {"content": "up"}}]})) as open_url:
                vultr.chat("worker", [{"role": "user", "content": "hello"}])
        self.assertEqual(open_url.call_args.args[0].get_header("Authorization"), "Bearer from-docs")

    def test_chat_json_extracts_fenced_object(self):
        with patch.object(vultr, "chat", return_value='```json\n{"decision":"deny","confidence":0.9}\n```'):
            self.assertEqual(vultr.chat_json("classifier", [{"role": "user", "content": "x"}])["decision"], "deny")

    def test_rerank_uses_documented_path_and_shape(self):
        response = {"results": [{"index": 1, "relevance_score": 3.0}]}
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "secret"}):
            with patch.object(vultr, "_open_request", return_value=FakeResponse(response)) as open_url:
                self.assertEqual(vultr.rerank("query", ["a", "b"], top_n=5), response["results"])
        request = open_url.call_args.args[0]
        self.assertTrue(request.full_url.endswith("/v1/rerank"))
        payload = json.loads(request.data)
        self.assertEqual(payload["model"], "bge-reranker-v2-m3")
        self.assertEqual(payload["top_n"], 2)
        self.assertEqual(payload["documents"], ["a", "b"])

    def test_missing_key_fails_before_network_call(self):
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "", "VULTR_SERVERLESS_INFERENCE_API_KEY": ""}):
            with patch.object(vultr, "_open_request") as open_url:
                with self.assertRaises(vultr.VultrConfigError):
                    vultr.chat("worker", [{"role": "user", "content": "hi"}])
                open_url.assert_not_called()

    def test_http_error_does_not_expose_key_or_prompt(self):
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "super-secret"}):
            with patch.object(vultr, "_open_request", side_effect=HTTPError("url", 401, "bad", {}, None)):
                with self.assertRaises(vultr.VultrAPIError) as caught:
                    vultr.chat("worker", [{"role": "user", "content": "private prompt"}])
        self.assertEqual(caught.exception.status, 401)
        self.assertNotIn("super-secret", str(caught.exception))
        self.assertNotIn("private prompt", str(caught.exception))

    def test_timeout_is_distinct_from_connection_failure(self):
        with patch.object(vultr, "_open_request", side_effect=URLError(socket.timeout())):
            with self.assertRaises(vultr.VultrTimeoutError):
                vultr.list_models()

    def test_malformed_response_is_rejected(self):
        with patch.object(vultr, "_open_request", return_value=FakeResponse({"choices": []})):
            with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "secret"}):
                with self.assertRaises(vultr.VultrResponseError):
                    vultr.chat("worker", [{"role": "user", "content": "hi"}])

    def test_smoke_does_not_print_key(self):
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "super-secret"}):
            with patch.object(vultr, "list_models", return_value=[{"id": "glm-5.3"}]):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(vultr.main(["smoke"]), 0)
        self.assertIn("Catalog: 1 models", output.getvalue())
        self.assertNotIn("super-secret", output.getvalue())

    def test_role_reasoning_defaults_leave_room_for_visible_output(self):
        response = FakeResponse({"choices": [{"message": {"content": "up"}}]})
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "secret", "VULTR_MODEL_SUPERVISOR": "glm-5.3-flash"}):
            with patch.object(vultr, "_open_request", return_value=response) as open_request:
                vultr.chat("supervisor", [{"role": "user", "content": "hello"}], max_tokens=160)
        payload = json.loads(open_request.call_args.args[0].data)
        self.assertEqual(payload["reasoning"], {"effort": "minimal", "max_tokens": 32})
        self.assertEqual(payload["max_completion_tokens"], 192)

    def test_deepseek_worker_disables_unbounded_reasoning(self):
        response = FakeResponse({"choices": [{"message": {"content": "{}"}}]})
        with patch.dict("os.environ", {"VULTR_INFERENCE_API_KEY": "secret", "VULTR_MODEL_WORKER": "deepseek-v4-flash-0731"}):
            with patch.object(vultr, "_open_request", return_value=response) as open_request:
                vultr.chat("worker", [{"role": "user", "content": "hello"}], max_tokens=256)
        payload = json.loads(open_request.call_args.args[0].data)
        self.assertEqual(payload["reasoning"], {"enabled": False})
        self.assertEqual(payload["max_completion_tokens"], 256)

    def test_redirect_never_forwards_bearer_to_another_origin(self):
        received = []

        class Sink(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Sink) as sink:
            sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
            sink_thread.start()
            destination = f"http://127.0.0.1:{sink.server_port}/sink"

            class Source(BaseHTTPRequestHandler):
                def do_POST(self):
                    self.send_response(307)
                    self.send_header("Location", destination)
                    self.end_headers()

                def log_message(self, *_args):
                    pass

            with ThreadingHTTPServer(("127.0.0.1", 0), Source) as source:
                source_thread = threading.Thread(target=source.serve_forever, daemon=True)
                source_thread.start()
                env = {"VULTR_INFERENCE_API_KEY": "super-secret",
                       "VULTR_INFERENCE_BASE_URL": f"http://127.0.0.1:{source.server_port}/v1"}
                with patch.dict("os.environ", env):
                    with self.assertRaises(vultr.VultrAPIError) as caught:
                        vultr.chat("supervisor", [{"role": "user", "content": "hello"}], max_tokens=8)
                self.assertEqual(caught.exception.status, 307)
                source.shutdown()
                source_thread.join(timeout=2)
            sink.shutdown()
            sink_thread.join(timeout=2)
        self.assertEqual(received, [])


if __name__ == "__main__":
    unittest.main()
