import copy
import random
import rsa
import tools

contact_list_format = {
    ("127.0.0.1", 4000): ["public_key", True]
}


class Phonebook:
    def __init__(self, base_contact_list=None):
        if base_contact_list is None:
            base_contact_list = dict()
        self._contact_list = base_contact_list
        self._exit_nodes = set()

    def get_contact_list(self):
        """
        Return the contact list and so the contacts and all information about them
        :return: contact_list
        """
        return self._contact_list

    def get_contacts(self):
        """
        Return every contact in the contact list
        :return: contacts
        """
        return [contact for contact in self._contact_list]

    def get_contact(self, public_key):
        """
        Return the contact linked to a given public key
        :param public_key:
        :return: contact
        """
        for contact in self._contact_list:
            if self._contact_list[contact][0] == public_key:
                return contact

    def get_info(self, contact):
        return self._contact_list[contact]

    def update_exit_nodes(self):
        new_exit_nodes = set()
        for contact in self._contact_list:
            if self._contact_list[contact][1]:
                new_exit_nodes.add(contact)

        self._exit_nodes = new_exit_nodes

    def update_contact_list(self, list_of_contact: dict):
        """
        Add new contacts to the actual contact list
        :param list_of_contact: New list of contact
        """
        new_contacts = []
        for new_contact in list_of_contact:
            if new_contact not in self._contact_list:
                new_contacts.append(new_contact)
                self._contact_list[new_contact] = list_of_contact[new_contact]

                if self._contact_list[new_contact][1]:
                    self._exit_nodes.add(new_contact)

        self.complete_contacts(new_contacts)

    def get_exit_nodes(self):
        return self._exit_nodes

    def get_updated_exit_nodes(self):
        self.update_exit_nodes()
        return self._exit_nodes

    def complete_contacts(self, addresses=None):
        """
        Ask the public key linked to the contact list addresses
        :param addresses:
        """
        if addresses is None:
            addresses = [address for address in self._contact_list]

        for contact in addresses:
            if contact in self._contact_list:
                if type(self._contact_list[contact][0]) is not rsa.PublicKey:
                    public_key = tools.request_from_node(contact, "public_key")
                    if type(public_key) is rsa.PublicKey:
                        self._contact_list[contact][0] = public_key
                    elif len(self._contact_list) > 3:
                        # Communication failed, suppose that node is offline, remove from phonebook
                        self.remove_address(contact)

    def define_path(self, path_length):
        """
        Define a path using the contact list
        :param path_length:
        :return: list_of_node
        """
        # tuple in the path list : (("127.0.0.1", 4000), [public_key, is_exit])
        list_of_node = [(contact, self.get_info(contact)) for contact in self.get_contacts()]
        random.shuffle(list_of_node)
        while len(list_of_node) > path_length:
            index = random.randrange(0, len(list_of_node), 1)
            list_of_node.pop(index)

        list_of_exit = list(self.get_updated_exit_nodes())
        if len(list_of_exit) > 0:
            random.shuffle(list_of_exit)
            exit_node = list_of_exit[random.randrange(0, len(list_of_exit), 1)] if len(list_of_exit) > 1 else list_of_exit[0]
            list_of_node.append((exit_node, self.get_info(exit_node)))
        else:
            raise ConnectionError("No exit node were found")

        if exit_node in [node[0] for node in list_of_node[:-1]]:
            list_of_node.remove((exit_node, self.get_info(exit_node)))  # remove first occurrence

        return list_of_node

    def remove_address(self, address):
        self._contact_list.pop(address)

    def add_address(self, address, public_key, is_exit_node=False):
        self._contact_list[address] = [public_key, is_exit_node]
