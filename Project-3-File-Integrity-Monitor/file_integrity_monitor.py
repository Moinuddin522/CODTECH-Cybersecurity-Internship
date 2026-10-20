"""
CODTECH Cybersecurity Internship
Project 3: File Integrity Monitor

Features:
- Calculates SHA-256 file hashes.
- Creates a baseline of files.
- Detects modified, new, and deleted files.
- Saves the baseline as JSON.
- Generates a scan report.
- Provides a simple graphical interface.

Use only on files and folders you are authorized to monitor.
"""

import hashlib
import json
import os
import tkinter as tk

from datetime import datetime
from tkinter import ttk, filedialog, messagebox


APP_TITLE = "CODTECH File Integrity Monitor"
BASELINE_FILE = "integrity_baseline.json"
REPORT_FOLDER = "reports"


def calculate_file_hash(file_path):
    """Calculate a file's SHA-256 hash."""
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (OSError, PermissionError):
        return None


def collect_file_hashes(folder_path):
    """Calculate hashes for files inside a folder and its subfolders."""
    results = {}
    errors = []

    for root, directories, filenames in os.walk(folder_path):
        # Skip folders commonly used for version control or caches.
        directories[:] = [
            directory
            for directory in directories
            if directory not in {".git", "__pycache__"}
        ]

        for filename in filenames:
            full_path = os.path.join(root, filename)

            relative_path = os.path.relpath(
                full_path,
                folder_path
            )

            file_hash = calculate_file_hash(full_path)

            if file_hash is not None:
                results[relative_path] = file_hash
            else:
                errors.append(relative_path)

    return results, errors


def save_json(data, filename):
    """Save data as formatted JSON."""
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def load_baseline(filename):
    """Load a saved baseline."""
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def create_report(folder_path, baseline, current, errors):
    """Compare hashes and create a report."""
    baseline_files = baseline["files"]

    baseline_names = set(baseline_files)
    current_names = set(current)

    added = sorted(current_names - baseline_names)
    deleted = sorted(baseline_names - current_names)

    modified = sorted(
        filename
        for filename in baseline_names & current_names
        if baseline_files[filename] != current[filename]
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "CODTECH FILE INTEGRITY MONITOR REPORT",
        "=" * 50,
        f"Folder monitored: {folder_path}",
        f"Report generated: {timestamp}",
        f"Files in baseline: {len(baseline_names)}",
        f"Files currently scanned: {len(current_names)}",
        "",
        f"Modified files: {len(modified)}",
    ]

    lines.extend(f"  [MODIFIED] {name}" for name in modified)

    lines.extend([
        "",
        f"New files: {len(added)}",
    ])

    lines.extend(f"  [NEW] {name}" for name in added)

    lines.extend([
        "",
        f"Deleted files: {len(deleted)}",
    ])

    lines.extend(f"  [DELETED] {name}" for name in deleted)

    lines.extend([
        "",
        f"Files that could not be read: {len(errors)}",
    ])

    lines.extend(f"  [READ ERROR] {name}" for name in errors)

    lines.extend([
        "",
        "NOTES",
        "-" * 50,
        "SHA-256 hashes are used to compare file contents.",
        "A changed hash indicates that the file contents differ.",
        "A new file is one absent from the baseline.",
        "A deleted file is one present in the baseline but absent now.",
        "Read errors may prevent complete comparison.",
    ])

    os.makedirs(REPORT_FOLDER, exist_ok=True)

    report_filename = datetime.now().strftime(
        os.path.join(REPORT_FOLDER, "integrity_report_%Y%m%d_%H%M%S.txt")
    )

    with open(report_filename, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    return report_filename, modified, added, deleted, errors


class FileIntegrityMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("760x570")
        self.root.minsize(650, 500)

        self.folder_path = tk.StringVar()
        self.status_text = tk.StringVar(
            value="Select a folder to begin."
        )

        self.build_interface()

    def build_interface(self):
        main = ttk.Frame(self.root, padding=18)
        main.pack(fill="both", expand=True)

        ttk.Label(
            main,
            text="File Integrity Monitor",
            font=("Arial", 20, "bold"),
        ).pack(pady=(0, 6))

        ttk.Label(
            main,
            text="Monitor file changes using SHA-256 hashes.",
        ).pack(pady=(0, 16))

        ttk.Label(
            main,
            text="Folder to monitor:",
        ).pack(anchor="w")

        folder_frame = ttk.Frame(main)
        folder_frame.pack(fill="x", pady=6)

        ttk.Entry(
            folder_frame,
            textvariable=self.folder_path,
        ).pack(side="left", fill="x", expand=True)

        ttk.Button(
            folder_frame,
            text="Browse",
            command=self.browse_folder,
        ).pack(side="left", padx=(8, 0))

        button_frame = ttk.Frame(main)
        button_frame.pack(pady=12)

        ttk.Button(
            button_frame,
            text="Create Baseline",
            command=self.create_baseline,
        ).grid(row=0, column=0, padx=5, pady=4)

        ttk.Button(
            button_frame,
            text="Check Integrity",
            command=self.check_integrity,
        ).grid(row=0, column=1, padx=5, pady=4)

        ttk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results,
        ).grid(row=0, column=2, padx=5, pady=4)

        ttk.Label(
            main,
            text="Results:",
            font=("Arial", 11, "bold"),
        ).pack(anchor="w", pady=(10, 4))

        self.results = tk.Text(
            main,
            height=15,
            wrap="word",
            state="disabled",
        )
        self.results.pack(fill="both", expand=True)

        ttk.Label(
            main,
            textvariable=self.status_text,
            wraplength=700,
        ).pack(anchor="w", pady=(10, 0))

        self.show_results(
            "Select a folder, then click Create Baseline.\n"
            "After making a test change, click Check Integrity."
        )

    def browse_folder(self):
        selected = filedialog.askdirectory(
            title="Select a folder to monitor"
        )

        if selected:
            self.folder_path.set(selected)

    def get_folder(self):
        folder = self.folder_path.get().strip()

        if not folder or not os.path.isdir(folder):
            messagebox.showerror(
                "Invalid Folder",
                "Please select an existing folder.",
            )
            return None

        # Prevent monitoring the application folder itself,
        # which contains its baseline and reports.
        application_folder = os.path.abspath(os.getcwd())
        selected_folder = os.path.abspath(folder)

        if (
            selected_folder == application_folder
            or os.path.commonpath(
                [application_folder, selected_folder]
            ) == selected_folder
        ):
            messagebox.showerror(
                "Choose Another Folder",
                "Select a test folder outside the application folder. "
                "This avoids scanning the baseline and report files.",
            )
            return None

        return selected_folder

    def show_results(self, text):
        self.results.config(state="normal")
        self.results.delete("1.0", tk.END)
        self.results.insert(tk.END, text)
        self.results.config(state="disabled")

    def create_baseline(self):
        folder = self.get_folder()

        if folder is None:
            return

        files, errors = collect_file_hashes(folder)

        baseline = {
            "folder": folder,
            "created": datetime.now().isoformat(timespec="seconds"),
            "algorithm": "SHA-256",
            "files": files,
        }

        try:
            save_json(baseline, BASELINE_FILE)
        except OSError as error:
            messagebox.showerror(
                "Save Error",
                f"Could not save the baseline:\n{error}",
            )
            return

        output = [
            "BASELINE CREATED",
            "=" * 40,
            f"Folder: {folder}",
            f"Files recorded: {len(files)}",
            f"Files with read errors: {len(errors)}",
            f"Baseline saved to: {BASELINE_FILE}",
            "",
            "Next: make a test change in the selected folder,",
            "then click Check Integrity.",
        ]

        if errors:
            output.extend([
                "",
                "Files that could not be read:",
                *errors,
            ])

        self.show_results("\n".join(output))
        self.status_text.set("Baseline created successfully.")

    def check_integrity(self):
        folder = self.get_folder()

        if folder is None:
            return

        if not os.path.isfile(BASELINE_FILE):
            messagebox.showwarning(
                "Baseline Missing",
                "Create a baseline before checking integrity.",
            )
            return

        try:
            baseline = load_baseline(BASELINE_FILE)
        except (OSError, json.JSONDecodeError) as error:
            messagebox.showerror(
                "Baseline Error",
                f"Could not read the baseline:\n{error}",
            )
            return

        if os.path.abspath(baseline.get("folder", "")) != folder:
            messagebox.showerror(
                "Folder Mismatch",
                "The selected folder differs from the saved baseline. "
                "Select the original folder or create a new baseline.",
            )
            return

        current, errors = collect_file_hashes(folder)

        try:
            report_path, modified, added, deleted, errors = create_report(
                folder,
                baseline,
                current,
                errors,
            )
        except OSError as error:
            messagebox.showerror(
                "Report Error",
                f"Could not save the report:\n{error}",
            )
            return

        lines = [
            "INTEGRITY CHECK COMPLETED",
            "=" * 40,
            f"Folder: {folder}",
            f"Files currently scanned: {len(current)}",
            "",
            f"Modified files: {len(modified)}",
        ]

        lines.extend(f"  [MODIFIED] {name}" for name in modified)

        lines.extend([
            "",
            f"New files: {len(added)}",
        ])

        lines.extend(f"  [NEW] {name}" for name in added)

        lines.extend([
            "",
            f"Deleted files: {len(deleted)}",
        ])

        lines.extend(f"  [DELETED] {name}" for name in deleted)

        lines.extend([
            "",
            f"Read errors: {len(errors)}",
        ])

        lines.extend(f"  [READ ERROR] {name}" for name in errors)

        lines.extend([
            "",
            f"Report saved to: {report_path}",
            "",
            "Note: Read errors may affect the completeness of the results.",
        ])

        self.show_results("\n".join(lines))
        self.status_text.set("Integrity check finished.")

    def clear_results(self):
        self.show_results("Results cleared.")
        self.status_text.set("Ready.")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityMonitor(root)
    root.mainloop()
