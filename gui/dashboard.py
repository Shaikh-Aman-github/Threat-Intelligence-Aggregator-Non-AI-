#Dashboard.py
import tkinter as tk
from tkinter import (messagebox, filedialog)
from pathlib import Path
from datetime import datetime
import os

from modules.pipeline import (
    ThreatIntelligencePipeline
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"
PDF_REPORT = OUTPUT_DIR / "final_report.pdf"


def start_gui():
    root = tk.Tk()
    root.title(
        "Threat Intelligence Aggregator"
    )
    root.geometry("1000x750")
    root.resizable(False, False)
    root.configure(
        bg="#f0f4f8"
    )

    # Header
    title = tk.Label(
        root,
        text="Threat Intelligence Aggregator",
        font=("Segoe UI", 26, "bold"),
        fg="#003366",
        bg="#f0f4f8"
    )
    title.pack(
        pady=15
    )
    subtitle = tk.Label(
        root,
        text="Threat Intelligence Feed Correlation & Blocklist Generator",
        font=("Segoe UI", 10),
        fg="#555555",
        bg="#f0f4f8"
    )
    subtitle.pack()

    # Statistics Frame
    stats_frame = tk.LabelFrame(
        root,
        text="Dashboard Statistics",
        font=("Segoe UI", 11, "bold"),
        padx=20,
        pady=10,
        bg="#f0f4f8"
    )
    stats_frame.pack(
        pady=15,
        padx=20,
        fill="x"
    )
    feeds_var = tk.StringVar(
        value="Feeds Processed : 0"
    )
    total_var = tk.StringVar(
        value="Total IOCs : 0"
    )
    unique_var = tk.StringVar(
        value="Unique IOCs : 0"
    )
    risk_var = tk.StringVar(
        value="High Risk IOCs : 0"
    )
    tk.Label(
        stats_frame,
        textvariable=feeds_var,
        font=("Segoe UI", 12),
        bg="#f0f4f8"
    ).pack(anchor="w")

    tk.Label(
        stats_frame,
        textvariable=total_var,
        font=("Segoe UI", 12),
        bg="#f0f4f8"
    ).pack(anchor="w")

    tk.Label(
        stats_frame,
        textvariable=unique_var,
        font=("Segoe UI", 12),
        bg="#f0f4f8"
    ).pack(anchor="w")

    tk.Label(
        stats_frame,
        textvariable=risk_var,
        font=("Segoe UI", 12),
        bg="#f0f4f8"
    ).pack(anchor="w")

    # Logs Section
    logs_title = tk.Label(
        root,
        text="Processing Logs",
        font=("Segoe UI", 12, "bold"),
        bg="#f0f4f8"
    )
    logs_title.pack()
    log_box = tk.Text(
        root,
        width=110,
        height=18,
        font=("Consolas", 10)
    )
    log_box.pack(
        padx=15,
        pady=10
    )
    log_box.insert(
        tk.END,
        "Ready...\n"
    )

    # Functions
    def write_log(message):
        log_box.insert(
            tk.END,
            f"{message}\n"
        )
        log_box.see(tk.END)
        root.update()

    def run_pipeline():
        try:
            log_box.delete(
                "1.0",
                tk.END
            )
            write_log(
                "Starting Threat Intelligence Pipeline..."
            )
            pipeline = (
                ThreatIntelligencePipeline()
            )
            stats = (
                pipeline.process_feeds()
            )
            if not stats:
                messagebox.showwarning(
                    "Warning",
                    "No IOC data processed."
                )
                return

            feeds_var.set(
                f"Feeds Processed : "
                f"{stats['feeds_processed']}"
            )
            total_var.set(
                f"Total IOCs : "
                f"{stats['total_iocs']}"
            )
            unique_var.set(
                f"Unique IOCs : "
                f"{stats['unique_iocs']}"
            )
            risk_var.set(
                f"High Risk IOCs : "
                f"{stats['high_risk']}"
            )

            if "logs" in stats:
                for log in stats["logs"]:
                    write_log(log)
            write_log(
                "\nPipeline completed successfully."
            )
            write_log(
                f"Completed at: "
                f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
            )
            status_var.set(
                "Status: Ready"
            )
        except Exception as error:
            status_var.set(
                "Status: Error"
            )
            messagebox.showerror(
                "Pipeline Error",
                str(error)
            )

    def upload_and_run_pipeline():
        try:
            file_paths = filedialog.askopenfilenames(
                title="Select IOC Feed Files",
                filetypes=[
                    (
                        "Supported Files",
                        "*.txt *.csv *.json *.stix"
                    ),
                    (
                        "Text Files",
                        "*.txt"
                    ),
                    (
                        "CSV Files",
                        "*.csv"
                    ),
                    (
                        "JSON Files",
                        "*.json"
                    ),
                    (
                        "STIX Files",
                        "*.stix"
                    )
                ]
            )

            if not file_paths:
                return
            write_log("Selected Feed(s):")
            for file in file_paths:
                write_log(f"• {os.path.basename(file)}")
            log_box.delete(
                "1.0",
                tk.END
            )
            write_log(
                "Processing Uploaded Feeds..."
            )
            pipeline = (
                ThreatIntelligencePipeline()
            )
            existing_btn.config(state="disabled")
            upload_btn.config(state="disabled")
            
            stats = (
                pipeline.process_uploaded_feeds(
                    list(file_paths)
                )
            )

            existing_btn.config(state="normal")
            upload_btn.config(state="normal")

            if not stats:
                messagebox.showwarning(
                    "Warning",
                    "No IOC data processed."
                )
                return

            feeds_var.set(
                f"Feeds Processed : "
                f"{stats['feeds_processed']}"
            )
            total_var.set(
                f"Total IOCs : "
                f"{stats['total_iocs']}"
            )
            unique_var.set(
                f"Unique IOCs : "
                f"{stats['unique_iocs']}"
            )
            risk_var.set(
                f"High Risk IOCs : "
                f"{stats['high_risk']}"
            )
            if "logs" in stats:
                for log in stats["logs"]:
                    write_log(
                        log
                    )
            write_log(
                "\nUploaded Feed Processing Complete."
            )
            write_log(
                f"Completed at: "
                f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
            )

            status_var.set(
                "Status: Ready"
            )

        except Exception as error:
            status_var.set(
                "Status: Error"
            )
            messagebox.showerror(
                "Upload Error",
                str(error)
            )

    def open_report():
        try:
            if PDF_REPORT.exists():
                os.startfile(
                    str(PDF_REPORT)
                )
            else:
                messagebox.showwarning(
                    "Report Missing",
                    f"Report not found:\n{PDF_REPORT}"
                )
        except Exception as error:
            messagebox.showerror(
                "Error",
                str(error)
            )

    def open_output_folder():
        try:
            if OUTPUT_DIR.exists():
                os.startfile(
                    str(OUTPUT_DIR)
                )
            else:
                messagebox.showwarning(
                    "Folder Missing",
                    "Output folder not found."
                )
        except Exception as error:
            messagebox.showerror(
                "Error",
                str(error)
            )

    # Buttons
    button_frame = tk.Frame(
        root,
        bg="#f0f4f8"
    )
    button_frame.pack(
        pady=10
    )
    button_style = {

        "width": 22,
        "height": 2,
        "font": ("Segoe UI", 10, "bold")
    }
    existing_btn = tk.Button(
        button_frame,
        text="Use Existing Feeds",
        command=run_pipeline,
        **button_style
    )
    existing_btn.grid(
        row=0,
        column=0,
        padx=10
    )
    upload_btn = tk.Button(
        button_frame,
        text="Upload Feed(s)",
        command=upload_and_run_pipeline,
        **button_style
    )
    upload_btn.grid(
        row=0,
        column=1,
        padx=10
    )

    tk.Button(
        button_frame,
        text="Open PDF Report",
        command=open_report,
        **button_style
    ).grid(
        row=0,
        column=2,
        padx=10
    )

    tk.Button(
        button_frame,
        text="Open Output Folder",
        command=open_output_folder,
        **button_style
    ).grid(
        row=0,
        column=3,
        padx=10
    )

    tk.Button(
        root,
        text="Exit",
        width=22,
        height=2,
        font=("Segoe UI", 10, "bold"),
        command=root.destroy
    ).pack(
        pady=10
    )

    # Status Bar
    status_var = tk.StringVar(
        value="Status: Ready"
    )
    status_bar = tk.Label(
        root,
        textvariable=status_var,
        bd=1,
        relief=tk.SUNKEN,
        anchor="w",
        bg="#d9e6f2"
    )
    status_bar.pack(
        side=tk.BOTTOM,
        fill=tk.X
    )

    # Footer
    footer = tk.Label(
        root,
        text="Unified Mentor Internship Project | Threat Intelligence Aggregator",
        font=("Segoe UI", 9),
        fg="#666666",
        bg="#f0f4f8"
    )
    footer.pack(
        side=tk.BOTTOM,
        pady=5
    )
    root.mainloop()

    