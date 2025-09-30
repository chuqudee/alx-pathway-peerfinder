from typing import List
from models import Learner

# In-memory queues
pair_queue: List[Learner] = []
group_queue: List[Learner] = []

def add_to_queue(learner: Learner):
    if learner.match_type == "pair":
        pair_queue.append(learner)
    elif learner.match_type == "group":
        group_queue.append(learner)

def get_eligible_learners(queue: List[Learner], group_size: int) -> List[Learner]:
    eligible = [l for l in queue if l.assessment_completed]
    return eligible[:group_size]

def remove_matched(queue: List[Learner], matched: List[Learner]):
    for l in matched:
        queue.remove(l)
