# Documentation only: the action plugin of the same name does the work.
DOCUMENTATION = r"""
module: win_powershell
short_description: Test stand-in for ansible.windows.win_powershell.
description: [See plugins/action/win_powershell.py.]
options:
  parameters:
    type: dict
    description: Script parameters.
  script:
    type: str
    description: The script, ignored.
author: imas
"""
