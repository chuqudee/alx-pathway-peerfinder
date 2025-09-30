import threading
import time
from queue_manager import pair_queue, group_queue, get_eligible_learners, remove_matched

def match_loop():
    while True:
        # Check for pair matches
        if len(pair_queue) >= 2:
            pair = get_eligible_learners(pair_queue, 2)
            if len(pair) == 2:
                print(f"[MATCHED PAIR] → {[l.name for l in pair]}")
                remove_matched(pair_queue, pair)

        # Check for group matches
        if len(group_queue) >= 5:
            group = get_eligible_learners(group_queue, 5)
            if len(group) == 5:
                print(f"[MATCHED GROUP] → {[l.name for l in group]}")
                remove_matched(group_queue, group)

        time.sleep(5)  # Check every 5 seconds

def start_worker():
    thread = threading.Thread(target=match_loop, daemon=True)
    thread.start()
