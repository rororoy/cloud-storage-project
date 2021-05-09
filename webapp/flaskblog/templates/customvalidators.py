class Length(object):
    def __init__(self, message=None):
        if not message:
            message = 'Your password should contain at least one upper case character, one number and one symbol.' % (min, max)
        self.message = message

    def __call__(self, form, field):
        password = field.data
        if not password.match('^[a-z0-9$-/:-?{-~!"^_`\[\]#\\]+$'):
            raise ValidationError(self.message)
