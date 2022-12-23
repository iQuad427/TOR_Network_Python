from node import Node
import node
from tools import BColors

starting_nodes = [entry for entry in node.starting_phonebook]
TIME_OUT = 10


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    # try:
    west_node = Node(starting_nodes[0], True)
    west_node.start()

    north_node = Node(starting_nodes[1], False)
    north_node.start()

    east_node = Node(starting_nodes[2], False)
    east_node.start()

    south_node = Node(starting_nodes[3], False)
    south_node.start()
    # except OSError:
    #     print(f"{BColors.FAIL}failed to start properly, wait a moment before trying again{BColors.ENDC}")
    #     return 1

    print(f"{BColors.OKGREEN}Launch successful{BColors.ENDC}")


if __name__ == '__main__':
    print(f"{BColors.WARNING}{BColors.BOLD}Starting TOR Network...{BColors.ENDC}")
    start_network()
