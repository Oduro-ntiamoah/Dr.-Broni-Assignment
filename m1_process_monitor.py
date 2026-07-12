import psutil
import time
import datetime
import logging

# --- Configuration ---
POLL_INTERVAL_SECONDS = 2   # how often to check for new processes
LOG_FILE = "esca_agent.log"

# --- Logging setup: write to both console and a log file ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)


def get_current_processes():
    """
    Returns a dict of {pid: process_info} for all currently running processes.
    process_info includes name and executable path where accessible.
    """
    current = {}
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "create_time"]):
        try:
            info = proc.info
            current[info["pid"]] = {
                "name": info["name"],
                "exe": info["exe"] or "unknown",
                "create_time": info["create_time"]
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process may have died between listing and reading info, or
            # we don't have permission to read it (e.g. root-owned process)
            continue
    return current


def main():
    logging.info("ESCA Agent M1 starting - polling every %ss", POLL_INTERVAL_SECONDS)

    known_pids = set(get_current_processes().keys())
    logging.info("Baseline established: %d processes currently running", len(known_pids))

    try:
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)
            current = get_current_processes()
            current_pids = set(current.keys())

            new_pids = current_pids - known_pids
            for pid in new_pids:
                proc = current[pid]
                timestamp = datetime.datetime.now().isoformat()
                logging.info(
                    "NEW PROCESS DETECTED | PID=%s | Name=%s | Path=%s | Time=%s",
                    pid, proc["name"], proc["exe"], timestamp
                )

            # Update baseline for next iteration
            known_pids = current_pids

    except KeyboardInterrupt:
        logging.info("ESCA Agent M1 stopped by user.")


if __name__ == "__main__":
    main()