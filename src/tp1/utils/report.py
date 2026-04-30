from fpdf import FPDF
from fpdf.enums import XPos, YPos

from src.tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT IDS - ANALYSE RESEAU"
        self.summary = summary

    def concat_report(self) -> str:
        return f"{self.title}\n\n{self.summary.rstrip()}\n"

    def generate(self) -> str:
        return self.concat_report()

    def save(self, filename: str | None = None) -> None:
        output = filename or self.filename
        if output.lower().endswith(".pdf"):
            self._save_pdf(output)
            return

        with open(output, "w", encoding="utf-8") as report_file:
            report_file.write(self.concat_report())

    def _save_pdf(self, filename: str) -> None:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, self.title, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

        self._write_summary(pdf)
        self._write_protocol_table(pdf)
        self._write_protocol_chart(pdf)
        self._write_ips(pdf)
        self._write_alerts(pdf)

        pdf.output(filename)

    def _write_section_title(self, pdf: FPDF, title: str) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", size=10)

    def _write_summary(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Resume")
        for line in self.summary.splitlines():
            pdf.multi_cell(0, 5, line or " ", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    def _write_protocol_table(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Tableau des protocoles")
        rows = self._protocol_rows()

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(80, 7, "Protocol", border=1)
        pdf.cell(40, 7, "Packets", border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_font("Helvetica", size=10)
        for protocol, count in rows:
            pdf.cell(80, 7, protocol, border=1)
            pdf.cell(40, 7, str(count), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    def _write_protocol_chart(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Graphique des protocoles")
        rows = self._protocol_rows()
        if not rows:
            pdf.cell(0, 6, "Aucune donnee a afficher.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
            return

        max_count = max(count for _, count in rows) or 1
        label_width = 40
        max_bar_width = 125
        bar_height = 7
        row_height = 11
        value_gap = 4
        x0 = pdf.get_x()
        y = pdf.get_y()
        bar_x = x0 + label_width

        pdf.set_font("Helvetica", size=9)
        pdf.set_fill_color(80, 130, 210)
        pdf.set_text_color(0, 0, 0)

        for protocol, count in rows:
            bar_width = (count / max_count) * max_bar_width if count else 0
            bar_y = y + 1

            pdf.set_xy(x0, y)
            pdf.cell(label_width, row_height, protocol)

            if bar_width:
                pdf.rect(bar_x, bar_y, bar_width, bar_height, style="F")
            pdf.set_xy(bar_x + bar_width + value_gap, y)
            pdf.cell(20, bar_height, str(count))
            y += row_height

        pdf.set_xy(x0, y + 4)

    def _protocol_rows(self) -> list[tuple[str, int]]:
        if not self.capture.protocol_counter:
            return [("UNKNOWN", 0)]
        return sorted(
            ((str(protocol), int(count)) for protocol, count in self.capture.protocol_counter.items()),
            key=lambda item: item[1],
            reverse=True,
        )

    def _write_ips(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Adresses IP")
        if not self.capture.ip_packet_counter:
            pdf.cell(0, 6, "Aucune adresse IP detectee.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
            return

        for address, count in sorted(self.capture.ip_packet_counter.items()):
            details = ", ".join(
                f"{protocol}: {protocol_count}"
                for protocol, protocol_count in sorted(
                    self.capture.ip_proto_counter.get(address, {}).items()
                )
            )
            pdf.multi_cell(
                0,
                6,
                f"{address}: {count} paquet(s) - {details}",
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
        pdf.ln(3)

    def _write_alerts(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Alertes")
        if not self.capture.suspicious:
            pdf.cell(0, 6, "Aucune attaque detectee.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            return

        for alert in self.capture.suspicious:
            pdf.multi_cell(0, 6, alert, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
