import csv


class IOCCorrelator:
    def correlate(
        self,
        normalized_iocs
    ):
        correlation = {}
        for ioc in normalized_iocs:
            indicator = ioc["indicator"]
            source = ioc["source"]
            if indicator not in correlation:
                correlation[indicator] = {
                    "sources": set(),
                    "type": ioc["type"]
                }
            correlation[indicator][
                "sources"
            ].add(source)
        return correlation

    def calculate_severity(
        self,
        source_count
    ):
        if source_count >= 3:
            return "High"
        elif source_count >= 2:
            return "Medium"
        return "Low"

    def build_report(
        self,
        normalized_iocs
    ):
        correlation = self.correlate(
            normalized_iocs
        )
        report = []
        for indicator, data in correlation.items():
            source_count = len(
                data["sources"]
            )
            report.append({
                "indicator": indicator,
                "type": data["type"],
                "sources_seen": source_count,
                "severity":
                self.calculate_severity(
                    source_count
                )
            })

        return sorted(
            report,
            key=lambda x: x[
                "sources_seen"
            ],
            reverse=True
        )

    def export_csv(
        self,
        report,
        output_file="output/correlation_report.csv"
    ):
        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "indicator",
                    "type",
                    "sources_seen",
                    "severity"
                ]
            )
            writer.writeheader()
            writer.writerows(
                report
            )

        print(
            f"\nCorrelation report saved: "
            f"{output_file}"
        )

        