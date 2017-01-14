from collections import namedtuple


class User(namedtuple('User', 'sid active token update_token')):
    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)

    def __repr__(self):
        return '<User: sid="{sid}" active="{active}" token="{token}" update_token="{update_token}">'.format(
            **self._asdict()
        )
