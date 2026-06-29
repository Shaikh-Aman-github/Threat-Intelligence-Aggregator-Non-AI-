#reporter.py
import uuid
from pathlib import Path
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.enums import (
    TA_CENTER,
    TA_LEFT
)
from datetime import datetime
from collections import Counter
from reportlab.lib.colors import HexColor
from reportlab.lib.units import inch
from modules.config import (OUTPUT_DIR)
class ThreatReporter:

    def header_footer(
        self,
        canvas,
        doc
    ):
        canvas.saveState()
        canvas.setFont(
            "Helvetica-Bold",
            10
        )
        canvas.drawString(
            40,
            820,
            "Threat Intelligence Aggregator"
        )
        canvas.drawRightString(
            560,
            820,
            "Unified Mentor Internship"
        )
        canvas.setFont(
            "Helvetica",
            8
        )
        canvas.drawString(
            40,
            20,
            "Generated : "
            + datetime.now().strftime(
                "%d-%m-%Y %H:%M"
            )
        )
        canvas.drawRightString(
            560,
            20,
            f"Page {doc.page}"
        )
        canvas.restoreState()
   
    def generate_pdf_report(
        self,
        normalized_iocs,
        correlation_report,
        output_file= OUTPUT_DIR / "final_report.pdf"
    ):
        output_file = Path(output_file)
        output_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        report_id = f"TI-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6].upper()}"

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
            str(output_file),
            rightMargin=40,
            leftMargin=40,
            topMargin=50,
            bottomMargin=40
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=HexColor("#003366"),
            fontSize=26,
            spaceAfter=20
        )
        heading = ParagraphStyle(
            "Heading",
            parent=styles["Heading2"],
            textColor=HexColor("#003366"),
            spaceBefore=10,
            spaceAfter=10
        )
        body = ParagraphStyle(
            "Body",
            parent=styles["BodyText"],
            fontSize=10,
            leading=18
        )

        elements = []
        elements.append(
            Spacer(1, 1.5 * inch)
        )
        elements.append(
            Paragraph(
                "Threat Intelligence Aggregator",
                title_style
            )
        )
        elements.append(
            Paragraph(
                "Threat Intelligence Feed Correlation & Blocklist Generator",
                styles["Heading2"]
            )
        )
        elements.append(
            Spacer(1, 0.8 * inch)
        )
        elements.append(
            Paragraph(
                "<b>Unified Mentor Internship Project</b>",
                body
            )
        )
        elements.append(
            Paragraph(
                f"Generated On : {datetime.now().strftime('%d %B %Y %H:%M:%S')}",
                body
            )
        )
        elements.append(
            Paragraph(
                "Version : 1.0",
                body
            )
        )
        elements.append(
            Paragraph(
                f"Report ID : {report_id}",
                body
            )
        )
        elements.append(
            Paragraph(
                "Prepared By : Aman Shaikh",
                body
            )
        )
        elements.append(
            Spacer(1, 1 * inch)
        )
        elements.append(
            Paragraph(
                "<font color='red'><b>CONFIDENTIAL</b></font>",
                styles["Title"]
            )
        )
        elements.append(
            PageBreak()
        )
        elements.append(
            Paragraph(
                "Executive Summary",
                heading
            )
        )
        summary = f"""
        This report summarizes the Threat Intelligence
        collected from multiple internal and external feeds.

        Indicators of Compromise (IOCs) were collected,
        validated, normalized, correlated and categorized.

        Repeated indicators were prioritized according
        to their occurrence across multiple feeds and
        exported into deployment-ready blocklists.

        The generated outputs can be directly used by
        SOC analysts, Firewalls, IDS/IPS, EDR solutions
        and other Blue Team defensive technologies.
        """
        elements.append(
            Paragraph(
                summary,
                body
            )
        )
        elements.append(
            Spacer(1,25)
        )
        elements.append(
            Paragraph(
                "Dashboard Summary",
                heading
            )
        )
        feed_sources = len(
            set(
                ioc["source"]
                for ioc in normalized_iocs
            )
        )
        dashboard_data = [
            [
                "Metric",
                "Value"
            ],
            [
                "Feed Sources Processed",
                str(feed_sources)
            ],
            [
                "Total Indicators",
                str(total_iocs)
            ],
            [
                "Unique Indicators",
                str(unique_iocs)
            ],
            [
                "High Risk Indicators",
                str(high_risk)
            ],
            [
                "Report Generated",
                datetime.now().strftime(
                    "%d-%m-%Y %H:%M"
                )
            ]
        ]
        dashboard_table = Table(
            dashboard_data,
            colWidths=[250,220]
        )
        dashboard_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#003366")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#EAF2F8")
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                ),
                (
                    "TOPPADDING",
                    (0,1),
                    (-1,-1),
                    8
                )
            ])
        )
        elements.append(
            dashboard_table
        )
        elements.append(
            Spacer(1,25)
        )

        elements.append(
            Paragraph(
                "IOC Statistics",
                heading
            )
        )
        type_counter = Counter(
            ioc["type"]
            for ioc in normalized_iocs
        )
        ioc_table_data = [
            [
                "IOC Type",
                "Count"
            ]
        ]
        for ioc_type,count in sorted(
            type_counter.items()
        ):
            ioc_table_data.append(
                [
                    ioc_type.upper(),
                    str(count)
                ]
            )
        ioc_table = Table(
            ioc_table_data,
            colWidths=[250,220]
        )
        ioc_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#005B96")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#F8F9F9")
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                )
            ])
        )
        elements.append(
            ioc_table
        )
        elements.append(
            PageBreak()
        )

        elements.append(
            Paragraph(
                "Severity Summary",
                heading
            )
        )
        high_count = len(
            [
                item
                for item in correlation_report
                if item["severity"] == "High"
            ]
        )
        medium_count = len(
            [
                item
                for item in correlation_report
                if item["severity"] == "Medium"
            ]
        )
        low_count = len(
            [
                item
                for item in correlation_report
                if item["severity"] == "Low"
            ]
        )
        severity_data = [
            [
                "Severity",
                "Indicators"
            ],
            [
                "High",
                str(high_count)
            ],
            [
                "Medium",
                str(medium_count)
            ],
            [
                "Low",
                str(low_count)
            ]
        ]
        severity_table = Table(
            severity_data,
            colWidths=[250,220]
        )
        severity_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#8B0000")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#FFF8DC")
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                )
            ])
        )
        elements.append(
            severity_table
        )
        elements.append(
            Spacer(1,25)
        )


        elements.append(
            Paragraph(
                "High Risk Indicators",
                heading
            )
        )
        high_risk_iocs = [
            item
            for item in correlation_report
            if item["severity"] == "High"
        ]

        if len(high_risk_iocs) == 0:
            elements.append(
                Paragraph(
                    "<b>No High Risk Indicators Found.</b>",
                    body
                )
            )
        else:
            high_table_data = [
                [
                    "Indicator",
                    "Type",
                    "Sources Seen",
                    "Severity"
                ]
            ]
            for item in high_risk_iocs:
                high_table_data.append(
                    [
                        item["indicator"],
                        item["type"].upper(),
                        str(item["sources_seen"]),
                        item["severity"]
                    ]
                )
            high_table = Table(
                high_table_data,
                colWidths=[220,70,90,80]
            )
            high_table.setStyle(
                TableStyle([
                    (
                        "BACKGROUND",
                        (0,0),
                        (-1,0),
                        HexColor("#8B0000")
                    ),
                    (
                        "TEXTCOLOR",
                        (0,0),
                        (-1,0),
                        colors.white
                    ),
                    (
                        "GRID",
                        (0,0),
                        (-1,-1),
                        0.5,
                        colors.black
                    ),
                    (
                        "BACKGROUND",
                        (0,1),
                        (-1,-1),
                        HexColor("#FFF5F5")
                    ),
                    (
                        "FONTNAME",
                        (0,0),
                        (-1,0),
                        "Helvetica-Bold"
                    ),
                    (
                        "BOTTOMPADDING",
                        (0,0),
                        (-1,0),
                        10
                    ),
                    (
                        "ALIGN",
                        (1,1),
                        (-1,-1),
                        "CENTER"
                    )
                ])
            )
            elements.append(
                high_table
            )
        elements.append(
            Spacer(1,25)
        )


        elements.append(
            Paragraph(
                "Top Correlated Indicators",
                heading
            )
        )
        elements.append(
            Paragraph(
                "The following table shows the most frequently observed "
                "Indicators of Compromise across all processed threat feeds.",
                body
            )
        )
        elements.append(
            Spacer(1,12)
        )
        correlated_table_data = [
            [
                "Indicator",
                "Type",
                "Sources",
                "Severity"
            ]
        ]
        sorted_report = sorted(
            correlation_report,
            key=lambda item: (
                item["sources_seen"],
                item["severity"]
            ),
            reverse=True
        )

        TOP_LIMIT = 50

        for item in sorted_report[:TOP_LIMIT]:
            correlated_table_data.append(
                [
                    item["indicator"],
                    item["type"].upper(),
                    str(item["sources_seen"]),
                    item["severity"]
                ]
            )

        correlated_table = Table(
            correlated_table_data,
            colWidths=[240,70,70,80]
        )

        correlated_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#003366")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#F8F9F9")
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                ),
                (
                    "ALIGN",
                    (1,1),
                    (-1,-1),
                    "CENTER"
                ),
                (
                    "VALIGN",
                    (0,0),
                    (-1,-1),
                    "MIDDLE"
                )
            ])
        )
        elements.append(
            correlated_table
        )
        elements.append(
            Spacer(1,12)
        )

        elements.append(
            Paragraph(
                f"<b>Note:</b> Only the Top {TOP_LIMIT} correlated indicators are "
                "displayed in this report. The complete IOC dataset is available in "
                "<i>normalized_iocs.json</i> and "
                "<i>correlation_report.csv</i>.",
                body
            )
        )
        elements.append(
            PageBreak()
        )


        elements.append(
            Paragraph(
                "Generated Output Files",
                heading
            )
        )
        elements.append(
            Paragraph(
                "The Threat Intelligence Aggregator generated the following output files "
                "during analysis. These files can be directly used for security operations "
                "and further investigation.",
                body
            )
        )
        elements.append(
            Spacer(1,15)
        )

        generated_files = [
            [
                "Output File",
                "Purpose"
            ],
            [
                "normalized_iocs.json",
                "Normalized IOC Database"
            ],
            [
                "correlation_report.csv",
                "IOC Correlation Results"
            ],
            [
                "ip_blocklist.txt",
                "Firewall IP Blocklist"
            ],
            [
                "domain_blocklist.txt",
                "Malicious Domain Blocklist"
            ],
            [
                "url_blocklist.txt",
                "Web Filter URL Blocklist"
            ],
            [
                "hash_blocklist.txt",
                "EDR / Antivirus Hash Blocklist"
            ],
            [
                "email_blocklist.txt",
                "Malicious Email Blocklist"
            ],
            [
                "blocklists.csv",
                "Combined IOC Blocklist (CSV)"
            ],
            [
                "blocklists.json",
                "Combined IOC Blocklist (JSON)"
            ]
        ]
        output_table = Table(
            generated_files,
            colWidths=[210,260]
        )
        output_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#006699")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#F4F6F7")
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                ),
                (
                    "TOPPADDING",
                    (0,1),
                    (-1,-1),
                    8
                ),
                (
                    "VALIGN",
                    (0,0),
                    (-1,-1),
                    "MIDDLE"
                )
            ])
        )
        elements.append(
            output_table
        )
        elements.append(
            Spacer(1,25)
        )
        elements.append(
            Paragraph(
                "<b>Note:</b> These output files are stored inside the project's "
                "<b>output</b> directory and are ready for deployment or further "
                "analysis by security teams.",
                body
            )
        )
        elements.append(
            PageBreak()
        )


        elements.append(
            Paragraph(
                "Security Recommendations",
                heading
            )
        )

        elements.append(
            Paragraph(
                "Based on the processed Threat Intelligence data, "
                "the following defensive actions are recommended "
                "to improve the organization's cybersecurity posture.",
                body
            )
        )
        elements.append(
            Spacer(1,15)
        )
        recommendation_data = [
            [
                Paragraph("<b>Recommendation</b>", body),
                Paragraph("<b>Description</b>", body)
            ],
            [
                Paragraph("Firewall Protection", body),
                Paragraph(
                    "Import IP Blocklists into perimeter firewalls "
                    "to automatically block malicious IP addresses.",
                    body
                )
            ],
            [
                Paragraph("Web Filtering", body),
                Paragraph(
                    "Import malicious URL and Domain blocklists "
                    "into Secure Web Gateway or DNS filtering solutions.",
                    body
                )
            ],
            [
                Paragraph("Endpoint Protection", body),
                Paragraph(
                    "Import malicious Hash Blocklists into EDR/AV products "
                    "to prevent execution of known malware.",
                    body
                )
            ],
            [
                Paragraph("Email Security", body),
                Paragraph(
                    "Use the generated Email Blocklist within Email Security"
                    "Gateway solutions.",
                    body
                )
            ],
            [
                Paragraph("SOC Monitoring", body),
                Paragraph(
                    "Monitor Medium and High severity indicators for "
                    "possible security incidents.",
                    body
                )
            ],
            [
                Paragraph("Threat Hunting", body),
                Paragraph(
                    "Search internal SIEM, EDR and IDS logs for correlated "
                    "indicators identified in this report.",
                    body
                )
            ],
               [
                Paragraph("Threat Feed Updates", body),
                Paragraph(
                    "Update Threat Intelligence feeds regularly to maintain "
                    "an up-to-date IOC database.",
                    body
                )
            ],
            [
                Paragraph("SIEM Integration", body),
                Paragraph(
                    "Integrate normalized IOC datasets with SIEM platforms "
                    "for automated alerting and correlation.",
                    body
                )
            ]
        ]
        recommendation_table = Table(
            recommendation_data,
            colWidths=[140,360]
        )
        recommendation_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#2E4053")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#FDFEFE")
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                ),
                (
                    "TOPPADDING",
                    (0,1),
                    (-1,-1),
                    8
                ),
                (
                    "VALIGN",
                    (0,0),
                    (-1,-1),
                    "TOP"
                )
            ])
        )
        elements.append(
            recommendation_table
        )
        elements.append(
            Spacer(1,20)
        )
        elements.append(
            Paragraph(
                "<b>Operational Note:</b> The generated IOC datasets and blocklists "
                "should be reviewed periodically and updated with the latest Threat "
                "Intelligence feeds to maintain an effective defensive posture.",
                body
            )
        )
        elements.append(
            PageBreak()
        )


        elements.append(
            Paragraph(
                "Conclusion",
                heading
            )
        )
        conclusion = """
        The Threat Intelligence Aggregator successfully collected,
        validated, normalized and correlated Indicators of Compromise
        (IOCs) from multiple Threat Intelligence feeds.

        The toolkit generated deployment-ready blocklists, exported
        normalized IOC datasets and produced an actionable Threat
        Intelligence Report.

        The generated outputs can be integrated into Firewalls,
        IDS/IPS, Secure Web Gateways, Endpoint Detection &
        Response (EDR), SIEM platforms and SOC workflows to
        strengthen an organization's security posture.

        The project demonstrates a practical implementation of
        Threat Intelligence aggregation and Blue Team defensive
        operations without using Artificial Intelligence or
        Machine Learning.
        """
        elements.append(
            Paragraph(
                conclusion,
                body
            )
        )
        elements.append(
            Spacer(1,25)
        )


        elements.append(
            Paragraph(
                "Appendix",
                heading
            )
        )
        appendix_data = [
            [
                "Generated Artifact",
                "Description"
            ],
            [
                "normalized_iocs.json",
                "Normalized IOC Database"
            ],
            [
                "correlation_report.csv",
                "IOC Correlation Report"
            ],
            [
                "ip_blocklist.txt",
                "Firewall Blocklist"
            ],
            [
                "domain_blocklist.txt",
                "Domain Blocklist"
            ],
            [
                "url_blocklist.txt",
                "URL Blocklist"
            ],
            [
                "hash_blocklist.txt",
                "Hash Blocklist"
            ],
            [
                "email_blocklist.txt",
                "Email Blocklist"
            ],
            [
                "blocklists.csv",
                "Combined CSV Export"
            ],
            [
                "blocklists.json",
                "Combined JSON Export"
            ]
        ]
        appendix_table = Table(
            appendix_data,
            colWidths=[220,250]
        )
        appendix_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#34495E")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#F8F9F9")
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                )
            ])
        )
        elements.append(
            appendix_table
        )
        elements.append(
            Spacer(1,20)
        )

       

        elements.append(
            Paragraph(
                "Report Metadata",
                heading
            )
        )
        metadata_data = [
            [
                "Property",
                "Value"
            ],
            [
                "Project",
                "Threat Intelligence Aggregator"
            ],
            [
                "Version",
                "1.0"
            ],
            [
                "Report ID",
                report_id
            ],
            [
                "Prepared By",
                "Aman Shaikh"
            ],
            [
                "Generated On",
                datetime.now().strftime("%d %B %Y %H:%M:%S")
            ],
            [
                "Programming Language",
                "Python"
            ],
            [
                "Database",
                "SQLite"
            ],
            [
                "Supported Feed Types",
                "TXT, CSV, JSON, STIX, URL"
            ]
        ]
        metadata_table = Table(
            metadata_data,
            colWidths=[180,290]
        )
        metadata_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    HexColor("#003366")
                ),
                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),
                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.black
                ),
                (
                    "BACKGROUND",
                    (0,1),
                    (-1,-1),
                    HexColor("#FCFCFC")
                ),
                (
                    "FONTNAME",
                    (0,0),
                    (-1,0),
                    "Helvetica-Bold"
                ),
                (
                    "BOTTOMPADDING",
                    (0,0),
                    (-1,0),
                    10
                )
            ])
        )
        elements.append(
            metadata_table
        )
        elements.append(
            Spacer(1,30)
        )
        elements.append(
            Paragraph(
                "<para align='center'><b>*************** END OF REPORT ***************</b></para>",
                styles["Heading2"]
            )
        )
        elements.append(
            Paragraph(
                "<para align='center'>Thank you for reviewing this Threat Intelligence Report.</para>",
                body
            )
        )
        elements.append(
            Spacer(1,20)
        )
        elements.append(
            Paragraph(
                "<para align='center'><font color='grey'>Generated by Threat Intelligence Aggregator Toolkit & Develop by Aman Shaikh</font></para>",
                styles["Italic"]
            )
        )


        pdf.build(
        elements,
            onFirstPage=self.header_footer,
            onLaterPages=self.header_footer
            )

        print(
             f"\nPDF Report Generated: {str(output_file)}"
        )