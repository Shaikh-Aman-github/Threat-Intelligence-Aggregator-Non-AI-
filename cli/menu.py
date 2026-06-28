import os

from modules.pipeline import (
    ThreatIntelligencePipeline
)


def start_cli():
    while True:
        print("\n")
        print("=" * 60)
        print(" Threat Intelligence Aggregator CLI ")
        print("=" * 60)

        print("1. Run Threat Intelligence Pipeline")
        # print("2. Parse Indicators")
        # print("3. Normalize Data")
        # print("4. Correlate Indicators")
        # print("5. Generate Blocklists")
        # print("6. Generate Report")
        print("7. Exit")

        choice = input(
            "\nEnter Choice: "
        )

        if choice == "1":
            print("\nFeed Source")
            print("1. Use Existing Feeds")
            print("2. Upload Feed(s)")
            feed_choice = input(
                "\nSelect Option: "
            )

            pipeline = (
                ThreatIntelligencePipeline()
            )

            if feed_choice == "1":
                pipeline.process_feeds()
            elif feed_choice == "2":
                file_paths = []
                print(
                    "\nEnter feed file paths."
                )
                print(
                    "Supported: "
                    ".txt, .csv, .json, .stix"
                )
                print(
                    "Type 'done' when finished.\n"
                )
                while True:
                    file_path = input(
                        "File Path: "
                    ).strip()
                    if file_path.lower() == "done":

                        break
                    if not os.path.exists(
                        file_path
                    ):
                        print(
                            "File not found."
                        )
                        continue
                    file_paths.append(
                        file_path
                    )

                if not file_paths:
                    print(
                        "\nNo files selected."
                    )
                    continue
                try:
                    stats = (
                        pipeline.process_uploaded_feeds(
                            file_paths
                        )
                    )
                    if stats:
                        print("\n")
                        print("=" * 40)
                        print(
                            f"Feeds Processed: "
                            f"{stats['feeds_processed']}"
                        )
                        print(
                            f"Total IOCs: "
                            f"{stats['total_iocs']}"
                        )
                        print(
                            f"Unique IOCs: "
                            f"{stats['unique_iocs']}"
                        )
                        print(
                            f"High Risk IOCs: "
                            f"{stats['high_risk']}"
                        )
                        print("=" * 40)
                except Exception as error:
                    print(
                        f"\nError: {error}"
                    )
            else:
                print(
                    "\nInvalid Feed Option"
                )
        elif choice == "2":
            print(
                "\nIndividual Parser Module "
                "will be added later."
            )
        elif choice == "3":
            print(
                "\nIndividual Normalizer Module "
                "will be added later."
            )
        elif choice == "4":
            print(
                "\nIndividual Correlation Module "
                "will be added later."
            )
        elif choice == "5":
            print(
                "\nIndividual Blocklist Module "
                "will be added later."
            )
        elif choice == "6":
            print(
                "\nIndividual Reporting Module "
                "will be added later."
            )
        elif choice == "7":
            print(
                "\nClosing CLI..."
            )
            break
        else:
            print(
                "\nInvalid Choice"
            )

            