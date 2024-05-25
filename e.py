def check_arguments_length(func):
    def wrapper(*args, **kwargs):
        # args[1] corresponds to the `arguments` parameter of the method
        if len(args[1]) == 0:
            raise ValueError(f"{func.__name__} requires at least one argument.")
        return func(*args, **kwargs)
    return wrapper

class CommandProcessor:
    
    @check_arguments_length
    def command_use(self, arguments):
        print(f"Using command with arguments: {arguments}")
        # Add the logic for the command_use method here

    @check_arguments_length
    def command_cd(self, arguments):
        print(f"Changing directory to: {arguments}")
        # Add the logic for the command_cd method here

# Example usage
processor = CommandProcessor()

try:
    processor.command_use(["arg1", "arg2"])  # This should work
    processor.command_cd([])  # This should raise a ValueError
except ValueError as e:
    print(e)
