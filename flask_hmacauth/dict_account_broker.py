__author__ = 'daslanian'


class DictAccountBroker(object):
    """
    Default minimal implementation of an AccountBroker. This implementation maintains a dict in memory with structure:
    {
        account_id:
            {
                secret: "some secret string",
                rights: ["someright", "someotherright"],
            },
        ...
    }
    Your implementation can use whatever backing store you like as long as you provide
    the following methods:

    get_secret(account_id) - returns a string secret given an account ID.  If the account does not exist, returns None
    has_rights(account_id, rights) - returns True if account_id has all of the rights in the list
        rights, otherwise returns False.  Returns False if the account does not exist.
    is_active(account_id) - returns True if account_id is active (for whatever definition you want
        to define for active), otherwise returns False.
    """

    def __init__(self, accounts=None):
        self.accounts = accounts or {}

    # TODO: test
    def add_accounts(self, accounts):
        self.accounts.update(accounts)

    # TODO: test
    def del_accounts(self, accounts):
        if isinstance(accounts, list):
            for i in accounts:
                del self.accounts[i]
        else:
            del self.accounts[accounts]

    def get_secret(self, account):
        try:
            secret = self.accounts[account]["secret"]
        except KeyError:
            return None
        return secret

    def has_rights(self, account, rights):
        try:
            account_rights = self.accounts[account]["rights"]
        except KeyError:
            return False
        if set(rights).issubset(account_rights):
            return True
        return False

    def is_active(self, account):
        if account in self.accounts:
            return True
        return False


class StaticAccountBroker(object):
    def __init__(self, secret=None):
        if secret is None:
            raise ValueError("you must provide a value for 'secret'")
        self._secret = secret

    def is_active(self, account):
        return True

    def get_secret(self, account):
        return self._secret

    def has_rights(self, account, rights):
        return True
