import os
import tempfile
from unittest.mock import MagicMock

from src.tp1.utils.report import Report


def _make_capture(protocols=None, ips=None, suspicious=None):
    capture = MagicMock()
    capture.protocol_counter = protocols or {"TCP": 10, "UDP": 5, "ARP": 3, "UNKNOWN": 2}
    capture.ip_packet_counter = ips or {"192.168.1.1": 8, "192.168.1.2": 10}
    capture.ip_proto_counter = {
        "192.168.1.1": {"TCP": 8},
        "192.168.1.2": {"TCP": 6, "UDP": 4},
    }
    capture.suspicious = suspicious if suspicious is not None else []

    proto_analysis = {}
    for proto, count in capture.protocol_counter.items():
        alerts = [alert for alert in capture.suspicious if proto in alert]
        proto_analysis[proto] = {
            "count": count,
            "status": "SUSPICIOUS" if alerts else "OK",
            "alerts": alerts,
        }
    capture.get_proto_analysis.return_value = proto_analysis
    return capture


def test_report_init():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    assert report.title == "RAPPORT IDS - ANALYSE RESEAU"
    assert report.summary == "Test summary"


def test_concat_report():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    assert report.concat_report() == "Test Title\n\nTest summary\n"


def test_save_txt():
    report = Report(MagicMock(), "test.txt", "Test summary")
    report.title = "Test Title"
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:
        tmp_path = tmp.name
    try:
        report.save(tmp_path)
        with open(tmp_path, "r") as f:
            assert f.read() == "Test Title\n\nTest summary\n"
    finally:
        os.unlink(tmp_path)


def test_save_pdf():
    capture = _make_capture()
    report = Report(capture, "test.pdf", "Test summary")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        report.save(tmp_path)
        assert os.path.exists(tmp_path)
        assert os.path.getsize(tmp_path) > 0
        with open(tmp_path, "rb") as f:
            assert f.read(4) == b"%PDF"
    finally:
        os.unlink(tmp_path)


def test_generate():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    assert report.generate() == report.concat_report()


def test_generate_pdf_contains_unknown():
    capture = _make_capture(protocols={"TCP": 10, "UDP": 5, "ARP": 3, "UNKNOWN": 2})
    report = Report(capture, "test.pdf", "Interface: eth0\nTotal packets captured: 20")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        report.save(tmp_path)
        assert os.path.exists(tmp_path)
        assert os.path.getsize(tmp_path) > 0
    finally:
        os.unlink(tmp_path)


class FakePdf:
    def __init__(self):
        self.calls = []
        self.x = 10
        self.y = 10

    def set_font(self, *args, **kwargs):
        self.calls.append(("set_font", args, kwargs))

    def cell(self, *args, **kwargs):
        self.calls.append(("cell", args, kwargs))

    def ln(self, value=0):
        self.calls.append(("ln", value))
        self.y += value

    def rect(self, *args, **kwargs):
        self.calls.append(("rect", args, kwargs))

    def set_fill_color(self, *args):
        self.calls.append(("set_fill_color", args))

    def set_text_color(self, *args):
        self.calls.append(("set_text_color", args))

    def get_x(self):
        return self.x

    def get_y(self):
        return self.y

    def set_xy(self, x, y):
        self.calls.append(("set_xy", x, y))
        self.x = x
        self.y = y


def test_pdf_protocol_table_contains_protocol_counts():
    capture = _make_capture(protocols={"TCP": 10, "UDP": 5, "ICMP": 3, "ARP": 2, "OTHER_132": 1})
    report = Report(capture, "test.pdf", "Test summary")
    pdf = FakePdf()

    report._write_protocol_table(pdf)

    cell_texts = [call[1][2] for call in pdf.calls if call[0] == "cell" and len(call[1]) >= 3]
    assert "Protocol" in cell_texts
    assert "Packets" in cell_texts
    assert "TCP" in cell_texts
    assert "10" in cell_texts
    assert "UDP" in cell_texts
    assert "5" in cell_texts
    assert "ICMP" in cell_texts
    assert "ARP" in cell_texts
    assert "OTHER_132" in cell_texts


def test_pdf_protocol_table_keeps_core_protocols_with_zero_packets():
    capture = _make_capture(protocols={"TCP": 0, "UDP": 128, "ICMP": 0, "ARP": 0})
    report = Report(capture, "test.pdf", "Test summary")
    pdf = FakePdf()

    report._write_protocol_table(pdf)

    cell_texts = [call[1][2] for call in pdf.calls if call[0] == "cell" and len(call[1]) >= 3]
    assert "TCP" in cell_texts
    assert "UDP" in cell_texts
    assert "ICMP" in cell_texts
    assert "ARP" in cell_texts
    assert "128" in cell_texts
    assert "0" in cell_texts


def test_pdf_protocol_chart_draws_bars():
    capture = _make_capture(protocols={"TCP": 10, "UDP": 5, "ICMP": 3, "ARP": 2, "OTHER_132": 1})
    report = Report(capture, "test.pdf", "Test summary")
    pdf = FakePdf()

    report._write_protocol_chart(pdf)

    rectangles = [call for call in pdf.calls if call[0] == "rect"]
    cell_texts = [call[1][2] for call in pdf.calls if call[0] == "cell" and len(call[1]) >= 3]
    colors = [call[1] for call in pdf.calls if call[0] == "set_fill_color"]
    assert len(rectangles) >= 2
    assert "TCP" in cell_texts
    assert "UDP" in cell_texts
    assert "ICMP" in cell_texts
    assert "ARP" in cell_texts
    assert "OTHER_132" in cell_texts
    assert (80, 130, 210) in colors
    assert rectangles[0][1][0] >= 50
    assert rectangles[0][1][2] > rectangles[1][1][2]
    assert rectangles[0][1][3] == 7
