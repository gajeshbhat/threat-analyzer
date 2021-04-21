"""
Multiple tables : Normalize

user : PRIMARY KEY user_id INT
      total_crated_job : INT

jobs : FORGIEN KEY : user_id
       job_id : INT (PRIMARY_KEY)
       machine_id : INT

hash_vals : PRIMARY key id:
            Job_id : FORGIEN KEY
            hash_value : VARCHAR(64)
            num_detect: INT
            endgine : FORGIEN IF  -- IF we want more engine details
            timestamp: DATE

Query :
SELECT hash_vals.hash_value,hash_vals.num_detect,hash_vals.engine,hash_Val.timestamp
FROM hash_val JOIN jobs j ON j.user_id = hash_vals.user_id WHERE hash_Vals.user_id = id AND j.job_id =hash_vals.job_id ;

Test Cases:
1. def check_file_input(file):
    actual_value =  check_for_file() -> Returns if the file is valid
    expected_Value = True
    assert(actual_value,expected_Value)


"""


import copy
class ListNode:
    def __init__(self,data,next):
        self.data  = data
        self.next = next

class Solution:
    """
    Naive Solution in Mind:
    1. Stacks -> GO through ll and push the elements to a stack
    2. Start from the list and pop the elements  of the stack and assign the value to the ll node.
    Pop: O(1)

     Time and Space : O(n) -> O(n) stack space

     4,5,1,9

    """
    def reverseList(self, head: ListNode):
        stack = [4,5,1,9]
        head_copy = copy(head)# Deep copy in py : Copy the actual value not just
        res = [9,1,5,4]
        if head is None or head.next == None:
            return head

        while head != None:
            stack.append(head.data)
            head = head.next
        while head_copy != None:
            head_copy.data = stack.pop()
            head_copy = head_copy.next
        return head_copy
