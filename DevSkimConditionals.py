"""
Copyright (c) 2017 Microsoft. All rights reserved.
Licensed under the MIT License. See LICENSE.txt in the project root for license information.

DevSkim Sublime Text Plugin
https://github.com/Microsoft/DevSkim-Sublime-Plugin
"""

import logging

try:
    import sublime
except Exception:
    print("Unable to import Sublime Text modules. DevSkim must be run within Sublime Text.")
    import sys
    sys.exit(1)

logger = logging.getLogger()

def condition__line_match_all(**kwargs):
    """Are all elements of targets substrings of line?"""
    line = kwargs.get('line')
    targets = kwargs.get('value')
    logger.debug('condition__line_match_all({%s}, {%s})', line, targets)

    line = line.lower()
    return all([t.lower() in line for t in targets])

def condition__line_match_any(**kwargs):
    """Are any elements of value substrings of line?"""
    line = kwargs.get('line')
    targets = kwargs.get('value')
    logger.debug('condition__line_match_any({%s}, {%s})', line, targets)

    line = line.lower()
    return any([t.lower() in line for t in targets])

def condition__line_match_none(**kwargs):
    """Are none of the elements of targets substrings of line?"""
    line = kwargs.get('line')
    targets = kwargs.get('value')
    logger.debug('condition__line_match_any({%s}, {%s})', line, targets)

    return not condition__line_match_any(**kwargs)

def condition__match_prefix_any(**kwargs):
    """Are any of the targets a prefix to the matched region?"""
    match_start = kwargs.get('match_start')
    targets = kwargs.get('value')
    view = kwargs.get('view')
    match_region = kwargs.get('match_region')

    for target in targets:
        region = sublime.Region(match_region.a - len(target), match_start)
        if view.substr(region).lower() == target.lower():
            return True
    return False
