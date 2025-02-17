from typing import Optional, Callable


class RecoverableTask:
    def __init__(self, do: Callable, undo: Callable, task_info: str = ''):
        self.do = do
        self.undo = undo
        self.task_info = task_info
    
    def execute(self) -> Optional[str]:
        error = None
        try:
            error = self.do()
        except Exception as err:
            return str(err)
        else:
            return error
    
    def undo(self) -> Optional[str]:
        error = None
        try:
            error = self.undo()
        except Exception as err:
            return str(err)
        else:
            return error

class Executor:
    def __init__(self):
        self.tasks = []
        self.has_error = False
    
    def add(self, task: RecoverableTask):
        self.tasks.append(task)
    
    def execute(self, without_debug: bool = False, dry_run: bool = False):
        index = 0
        for task in self.tasks:
            if dry_run:
                print(f'Will execute {index}: {task.task_info}...')
            else:
                if not without_debug:
                    print(f'Executing {index}: {task.task_info}...')
                error = task.execute()
                if error:
                    print(f'Error: {task.task_info} --> {error}')
                    self.has_error = True
                    if index > 0 and not without_debug:
                        print('\nUndoing previous tasks...')
                        self.undo(index)
                    elif not without_debug:
                        print('Nothing to undo')
                    break
                    
            index += 1
            
    def undo(self, fromidx: int):
        index = fromidx-1
        for task in reversed(self.tasks[:fromidx]):
            print(f'Undoing {index}: {task.task_info}...')
            error = task.undo()
            if error:
                print(f'Error: {error}')
                print('Engine might be left in an inconsistent state')
            
            index -= 1

    def list_tasks(self):
        index = 0
        for task in self.tasks:
            print(f'{index}: {task.task_info}')
            index += 1
        
