#reporter.py
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

class ThreatReporter:

    def generate_pdf_report(
        self,
        normalized_iocs,
        correlation_report,
        output_file="output/final_report.pdf"
    ):
        total_iocs = len(
            normalized_iocs
        )

        unique_iocs = len(
            set(
                ioc["indicator"]
                for ioc in normalized_iocs
            )
        )

        high_risk = len(
            [
                item
                for item in correlation_report
                if item["severity"] == "High"
            ]
        )    
        pdf = SimpleDocTemplate(
            output_file
        )

        styles = getSampleStyleSheet()

        content = []

        content.append(

            Paragraph(
                "Threat Intelligence Report",
                styles["Title"]
            )
        )

        content.append(
            Spacer(1, 20)
        )
        content.append(
            Paragraph(
                f"Total IOCs: {total_iocs}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Unique IOCs: {unique_iocs}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"High Risk Indicators: {high_risk}",
                styles["BodyText"]
            )
        )

        content.append(
            Spacer(1, 20)
        )
        content.append(
            Paragraph(
                "Top Correlated Indicators",
                styles["Heading2"]
            )
        )

        for item in sorted(
            correlation_report,
            key=lambda x: x["sources_seen"],
            reverse=True
        ):

            content.append(

                Paragraph(

                    f"""
                    Indicator: {item['indicator']}
                    <br/>
                    Type: {item['type']}
                    <br/>
                    Sources Seen: {item['sources_seen']}
                    <br/>
                    Severity: {item['severity']}
                    """,

                    styles["BodyText"]
                )
            )

            content.append(
                Spacer(1, 8)
            )
        pdf.build(content)

        print(
            f"\nPDF Report Generated: "
            f"{output_file}"
        )