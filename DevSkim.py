"""
Copyright (c) 2017 Microsoft. All rights reserved.
Licensed under the MIT License. See LICENSE.txt in the project root for license information.

DevSkim Sublime Text Plugin
https://github.com/Microsoft/DevSkim-Sublime-Plugin
"""

import datetime
import fnmatch
import json
import logging
import re
import time
import os
import shlex
import subprocess
import traceback
import webbrowser

try:
    import sublime
    import sublime_plugin
except Exception as _:
    print("Unable to import Sublime Text modules. DevSkim must be run within Sublime Text.")
    import sys
    sys.exit(1)

from . import DevSkimConditionals

# Non-Configurable Settings
MIN_ST_VERSION = 3114
MARK_FLAGS = sublime.DRAW_NO_FILL | sublime.HIDE_ON_MINIMAP
LOG_FORMAT = '%(asctime)-15s: %(levelname)s: %(name)s.%(funcName)s: %(message)s'
SEVERITY_LIST = ["critical", "important", "moderate", "low",
                 "defense-in-depth", "informational", "manual-review"]
RULE_DIRECTORY = ['default', 'custom']
DEVSKIM_RULES_DIR_PREFIX = 'DevSkim-Common/rules/'

# Minimum Sublime Text version we support
if int(sublime.version()) < MIN_ST_VERSION:
    raise RuntimeError('DevSkim requires Sublime Text 3 v%d or later.' %
                       MIN_ST_VERSION)

# Global Properties

devskim_event_listener = None

# Global logger
logger = logging.getLogger(__name__)

# Cache of user settings (sublime-provided)
user_settings = None

# Global objects, used for caching
rules = []

# Was the applies_to_ext_mapping already loaded from syntax files?
applies_to_ext_mapping_initialized = False

# Mapping between symbolic names ("csharp") and what they actually mean.
# This map is updated to include runtime syntax files, so this is just
# a starting point.
applies_to_ext_mapping = {
    "aspnet": {
        "syntax": [],
        "extensions": ["aspx"]
    },
    "powershell": {
        "syntax": ["Packages/PowerShell/PowerShell.sublime-syntax"],
        "extensions": ["ps1"]
    },
    "ruby": {
        "syntax": [],
        "extensions": ["erb"]
    },
    "swift": {
        "syntax": ["Packages/Swift/Swift.sublime-syntax"],
        "extensions": ["swift"]
    }
}
applies_to_ext_alias = {
    "c": "c++",
    "cpp": "c++",
    "csharp": "c#",
    "ios": "objective-c++",
    "objective-c": "objective-c++"
}

# Currently marked regions
marked_regions = []

# Cached stylesheet content
stylesheet_content = ""

# Cache suppress days
suppress_days = []

# Conditional Functions
conditional_func_map = {}


class DevSkimEventListener(sublime_plugin.EventListener):
    """Handles events from Sublime Text."""

    # Reference to the current view
    view = None

    def __init__(self, *args, **kwargs):
        """Initialize events listener."""
        super(DevSkimEventListener, self).__init__(*args, **kwargs)
        logger.debug("DevSkimEventListener.__init__()")

    def lazy_initialize(self):
        """Perform lazy initialization."""
        global rules, user_settings, stylesheet_content, suppress_days
        global applies_to_ext_mapping, applies_to_ext_mapping_initialized

        # logger.debug('lazy_initialize')

        if not user_settings:
            user_settings = sublime.load_settings('DevSkim.sublime-settings')
            if not user_settings:
                logger.warning("Unable to load DevSkim settings.")
                return

        user_settings.clear_on_change('DevSkim')
        user_settings.add_on_change('DevSkim', self.lazy_initialize)

        if not rules or len(rules) == 0:
            self.load_rules()

        if not applies_to_ext_mapping_initialized:
            self.load_syntax_mapping()
            applies_to_ext_mapping_initialized = True

        if not stylesheet_content:
            if not user_settings:
                logger.warning("Unable to load DevSkim settings.")
                return
            css_file = user_settings.get('style', 'dark.css')
            stylesheets = sublime.find_resources(css_file)
            if stylesheets:
                stylesheet_content = sublime.load_resource(stylesheets[0])
                stylesheet_content = stylesheet_content.replace('\r\n', '\n')
                logger.debug("Stylesheet: [%s]", stylesheet_content)
            else:
                stylesheet_content = ""
                logger.debug("No stylesheet found.")

        if not suppress_days:
            if not user_settings:
                logger.warning("Unable to load DevSkim settings.")
                return
            suppress_days = user_settings.get('suppress_days', [90, 365, -1])
            logger.debug('Suppress Days: %s', suppress_days)

        # Initialize the logger
        if len(logger.handlers) == 0:
            root_logger = logging.getLogger()
            console = logging.StreamHandler()
            console.setFormatter(logging.Formatter(LOG_FORMAT))

            if user_settings.get('debug', False):
                root_logger.setLevel(logging.DEBUG)
            else:
                root_logger.setLevel(logging.WARNING)

            logger.handlers = []
            logger.addHandler(console)

        # Initialize the conditionals
        for func in dir(DevSkimConditionals):
            if func.startswith('condition__'):
                func_short = func.replace('condition__', '')
                conditional_func_map[func_short] = getattr(DevSkimConditionals, func)

    def clear_regions(self, view):
        """Clear all regions."""
        global marked_regions, finding_list

        logger.debug("clear_regions()")

        if view:
            view.erase_regions("devskim-marks")
            marked_regions = []
            finding_list = []

    def on_selection_modified(self, view):
        """Handle selection change events."""
        global marked_regions, finding_list

        self.lazy_initialize()

        try:
            # Get the current region (cursor start)
            cur_region = view.sel()[0]

            for region in marked_regions:
                if region.contains(cur_region):
                    for finding in finding_list:
                        if finding.get("match_region") != region:
                            continue
                        rule = finding.get('rule')
                        view.set_status("DevSkim", "DevSkim: %s" % rule.get("name"))
                        return

            # We're not in a marked region, clear the status bar
            view.erase_status("DevSkim")

        except Exception as msg:
            logger.warning("Error in on_selection_modified: %s", msg)

    def on_navigate(self, command):
        """Handle navigation events."""
        global finding_list, rules, user_settings
        self.lazy_initialize()

        logger.debug("on_navigate(%s)", command)

        if not command:
            return

        command = command.strip()

        # Open a regular URL in the user's web browser
        if re.match("^https?://", command, re.IGNORECASE):
            webbrowser.open_new(command)
            return

        # Special commands, intercept and perform the fix
        if command.startswith('#fixit'):
            rule_id, fixid, region_start, region_end = command.split(',')[1:]
            fixid = int(fixid)
            region_start = int(region_start)
            region_end = int(region_end)

            for finding in finding_list:
                rule = finding.get('rule')

                # We're only searching for a specific rule id
                if rule.get('id') != rule_id:
                    continue

                contents = self.view.substr(sublime.Region(region_start, region_end))
                logger.debug("Applying fixit to contents [{0}]".format(contents))

                fixit = rule.get('fix_it')
                if not fixit or fixid >= len(fixit):
                    continue

                fixit = fixit[fixid]
                if not fixit:
                    logger.warn("Tried to apply fixit #{%s}, but was not found in dict.", fixid)
                    continue

                if fixit['type'] == 'regex-substitute':
                    search = fixit.get('search')
                    replace = fixit.get('replace')
                    flags = self.re_modifiers_to_flags(fixit.get('modifiers', []))

                    for k in range(1, 9):
                        replace = replace.replace("${0}".format(k), "\\{0}".format(k))

                    result = re.sub(search, replace, contents, flags=flags)
                    logger.debug("Result of search/replace was [%s]", result)

                    self.view.run_command('replace_text', {
                        'a': region_start,
                        'b': region_end,
                        'result': result
                    })
                else:
                    logger.warn("Invalid fixit type found, {0}".format(fixit['type']))

                self.view.hide_popup()
                self.clear_regions(self.view)
                self.view.sel().clear()

                # Only fix once
                break

        elif command.startswith('#add-reviewed'):
            rule_id, region_start = command.split(',')[1:]
            cur_line = self.view.line(int(region_start))

            comment = "  DevSkim: reviewed %s on %s " % (rule_id, datetime.datetime.now().strftime("%Y-%m-%d"))

            username = user_settings.get('manual_reviewer_name', '')
            if username == '':
                try:
                    import getpass
                    username = getpass.getuser()
                except:
                    pass

            if username:
                comment += "by {0} ".format(username)

            # Add the pragma/comment at the end of the current line
            self.view.run_command('insert_text', {
                'a': cur_line.b,
                'result': comment
            })

            # Now highlight that new section
            prev_sel = self.view.sel()
            self.view.sel().clear()
            self.view.sel().add(sublime.Region(cur_line.b + 1, cur_line.b + len(comment)))

            # Now make it a block comment
            self.view.run_command('toggle_comment', {'block': True})
            self.view.sel().clear()
            self.view.sel().add_all(prev_sel)

            self.view.hide_popup()

        elif command.startswith('#add-suppression'):
            rule_id, region_start, suppress_day = command.split(',')[1:]
            cur_line = self.view.line(int(region_start))

            # Ignore suppression for this many days from today
            try:
                suppress_day = int(suppress_day)
            except Exception as msg:
                suppress_day = -1

            if suppress_day == -1:  # Permanent suppression
                comment = "  DevSkim: ignore %s " % rule_id
            else:
                until_day = datetime.date.today() + datetime.timedelta(days=suppress_day)
                comment = "  DevSkim: ignore %s until %s " % (rule_id, until_day.strftime("%Y-%m-%d"))

            # Add the pragma/comment at the end of the current line
            self.view.run_command('insert_text', {
                'a': cur_line.b,
                'result': comment
            })

            # Now highlight that new section
            prev_sel = self.view.sel()
            self.view.sel().clear()
            self.view.sel().add(sublime.Region(cur_line.b + 1, cur_line.b + len(comment)))

            # Now make it a block comment
            self.view.run_command('toggle_comment', {'block': True})
            self.view.sel().clear()
            self.view.sel().add_all(prev_sel)

            self.view.hide_popup()

        else:
            logger.debug("Invalid command: %s", command)

    def on_modified(self, view):
        """Handle immedate analysis (on keypress)."""
        global user_settings

        # if view.change_count() % 10 != 0:
        #    return

        self.lazy_initialize()

        if user_settings.get('show_highlights_on_modified', False):
            try:
                self.analyze_current_view(view, show_popup=False, single_line=True)
            except Exception as msg:
                logger.warning("Error analyzing current view: %s", msg)
                traceback.print_exc()

    def on_load_async(self, view):
        """Handle asynchronous loading event."""
        global user_settings
        self.lazy_initialize()

        if user_settings.get('show_highlights_on_load', False):
            try:
                self.analyze_current_view(view, show_popup=False)
            except Exception as msg:
                logger.warning("Error analyzing current view: %s", msg)
                traceback.print_exc()

    def on_post_save_async(self, view):
        """Handle post-save events."""
        global user_settings
        self.lazy_initialize()

        logger.debug("on_post_save_async()")

        if user_settings.get('show_findings_on_save', True):
            try:
                self.analyze_current_view(view)
            except Exception as msg:
                logger.warning("Error analyzing current view: %s", msg)
                traceback.print_exc()

    def analyze_current_view(self, view, show_popup=True, single_line=False):
        """Kick off the analysis."""
        global marked_regions, finding_list, user_settings

        logger.debug("analyze_current_view()")
        self.lazy_initialize()

        if view is None or view.window() is None:
            # Early abort if we don't have a View and Window
            return

        window = view.window()

        if not single_line:
            self.clear_regions(view)

        filename = window.extract_variables().get('file', '').replace('\\', '/')
        if filename and self.is_file_ignored(filename):
            logger.debug("File is ignored.")
            return

        # Time the execution of this function
        start_time = time.clock()

        self.view = view

        # Check for files too large to scan
        max_size = user_settings.get('max_size', 524288)
        if 0 < max_size < view.size():
            logger.debug("File was too large to scan (%d bytes)", view.size())
            return

        window = self.view.window()
        if window is None:
            return

        extension = window.extract_variables().get('file_extension', '')

        show_severity = user_settings.get('show_severity', SEVERITY_LIST)

        # File syntax type
        syntax = view.settings().get('syntax')

        # Reset the UI (except if analyzing only a single line)
        if not single_line:
            self.clear_regions(view)
        finding_list = []

        # Grab the full file as a region
        full_region = sublime.Region(0, view.size())

        # Reset the marked regions for this view
        if not single_line:
            marked_regions = []

        if single_line:
            file_contents = view.substr(view.line(view.sel()[0]))
            logger.debug("Single line: [%s]", file_contents)
            offset = view.line(view.sel()[0]).begin()
        else:
            # Send the entire file over to DevSkim.execute
            file_contents = view.substr(full_region)
            logger.debug("File contents, size [%d]", len(file_contents))
            offset = 0

        result_list = []
        try:
            _v = window.extract_variables()
            filename = _v.get('file', '').replace('\\', '/')
            force_analyze = (extension == 'test' and
                             'DevSkim' in filename and
                             '/tests/' in filename)
            result_list = self.execute(file_contents, filename, extension, syntax,
                                       show_severity, force_analyze, offset)
            logger.debug("DevSkim retured: [%s]", result_list)
        except Exception as ex:
            logger.warning("Error executing DevSkim: [%s]", ex)
            traceback.print_exc()

        # rule['overrides'] logic
        overrides_list = []

        # This is a bug -- how should we handle this?
        for result in result_list:
            if 'overrides' in result['rule']:
                overrides_list += result['rule']['overrides']

        original_result_list_count = len(result_list)
        for rule_id in overrides_list:
            # Remove all results that match a id in the overrides_list
            result_list = list(filter(lambda r: r['rule']['id'] != rule_id,
                               result_list))

        if original_result_list_count > len(result_list):
            logger.debug("Reduced result list from [%d] to [%d] by overriding rules",
                         original_result_list_count, len(result_list))

        for result in result_list:
            # Narrow down to just the matching part of the line
            scope_name = view.scope_name(result.get('match_region').begin())

            scope_list = ["%s." % s for s in result.get('scope_list')]
            logger.debug("Current Scope: [%s], Applies to: %s", scope_name, scope_list)

            # Don't actually include if we're in a comment, or a quoted string, etc.
            if any([x in scope_name for x in scope_list]) or not scope_list:
                marked_regions.append(result.get('match_region'))
                finding_list.append(result)

        logger.debug("Set marked regions to: %s" % marked_regions)

        # Add a region (squiggly underline)
        view.add_regions("devskim-marks",
                         marked_regions,
                         "string",
                         user_settings.get('gutter_mark', 'dot'),
                         flags=MARK_FLAGS)

        shown_finding_list = []

        # Sort the findings
        if len(marked_regions) > 0:
            sort_by = user_settings.get('sort_results_by', 'line_number')
            if sort_by == 'severity':
                finding_list.sort(key=lambda s: SEVERITY_LIST.index(s.get('rule').get('severity')))
            elif sort_by == 'line_number':
                finding_list.sort(key=lambda s: view.rowcol(s.get('match_region').begin())[0])
            logger.debug("Findings have been sorted.")

        for finding in finding_list:
            rule = finding.get('rule')
            region_start = finding.get("match_region").begin()
            region = view.rowcol(region_start)
            severity = rule.get('severity', 'informational')
            severity = self.severity_abbreviation(severity).upper()

            shown_finding_list.append([rule.get("name"), "%d: %s" %
                                       (region[0] + 1,
                                       view.substr(view.line(region_start)).strip())])

        logger.debug("shown_findings_list has been created.")

        if show_popup:
            window.show_quick_panel(shown_finding_list, self.on_selected_result)

        end_time = time.clock()
        logger.debug("Elapsed time: %f" % (end_time - start_time))

    def on_selected_result(self, index):
        """Handle when the user clicks on a finding from the popup menu."""
        global finding_list, stylesheet_content, user_settings
        self.lazy_initialize()

        if index == -1:
            return

        chosen_item = finding_list[index]
        target_region = chosen_item.get('match_region')

        self.view.sel().clear()
        self.view.sel().add(target_region)
        self.view.show(target_region)

        rule = chosen_item['rule']

        # Create a guidance popup
        guidance = ['<body id="devskim-popup">']

        if stylesheet_content:
            guidance.append('<style>%s</style>' % stylesheet_content)

        guidance.append("<h3>%s</h3>" % rule.get('name', 'Missing rule name'))
        guidance.append('<p>%s</p>' % rule.get('description', '<i>Missing rule description</i>'))

        if rule.get('replacement'):
            guidance.append('<p>%s</p>' % rule['replacement'])

        if rule.get('fix_it'):
            guidance.append('<h3>Options:</h3>')
            guidance.append("<ul>")
            for fixid, fix in enumerate(rule.get('fix_it')):
                guidance.append('<li>Auto-Fix: <a href="#fixit,%s,%d,%d,%d">%s</a></li>' %
                                (rule.get('id'), fixid, target_region.begin(), target_region.end(), fix.get('name')))
            guidance.append("</ul>")

        # Supression links
        this_suppression_links = []
        all_suppression_links = []
        for suppress_day in suppress_days:
            suppress_day_str = "%d days" % suppress_day if suppress_day != -1 else "permanently"
            this_suppression_links.append('[ <a href="#add-suppression,%s,%d,%d">%s</a> ] ' %
                                          (rule.get('id'), target_region.a, suppress_day, suppress_day_str))
            all_suppression_links.append('[ <a href="#add-suppression,all,%d,%d">%s</a> ] ' %
                                         (target_region.a, suppress_day, suppress_day_str))

        guidance.append("<ul>")
        if rule.get('severity') == 'manual-review':
            guidance.append('<li><a href="#add-reviewed,{0},{1}">Mark finding as reviewed</a></li>'.format(rule.get('id'), target_region.a))
        else:
            if user_settings.get('allow_suppress_specific_rules'):
                guidance.append("<li>Supress this rule for: %s</li>" % (''.join(this_suppression_links)))
            if user_settings.get('allow_suppress_all_rules'):
                guidance.append("<li>Supress all rules for: %s</li>" % (''.join(all_suppression_links)))
        guidance.append('</ul>')


        if rule.get('rule_info'):
            guidance.append('<h4><a href="%s">Learn More...</a></h4>' % rule.get('rule_info'))
        elif user_settings.get('debug', False):
            guidance.append('<h4>Rule: %s</h4>' % rule.get('id'))

        guidance.append('</body>')

        sublime.set_timeout_async(lambda: self.ds_show_popup(''.join(guidance),
                                                             location=target_region.end(),
                                                             max_width=860,
                                                             max_height=560,
                                                             on_navigate=self.on_navigate,
                                                             flags=sublime.HTML), 0)

    def load_rules(self, force_reload=False):
        """Reload ruleset from the JSON configuration files."""
        global rules, user_settings

        if not force_reload and len(rules) > 0:
            logger.debug("Rules already loaded, no need to reload.")
            return False

        logger.debug('DevSkimEngine.load_rules()')

        if not user_settings:
            logger.warning("Settings not found, cannot load rules.")
            return False

        json_filenames = sublime.find_resources("*.json")
        rule_filenames = []
        for filename in json_filenames:
            for _dir in RULE_DIRECTORY:
                if (DEVSKIM_RULES_DIR_PREFIX + _dir) in filename:
                    rule_filenames.append(filename)

        # Remove duplicates
        rule_filenames = list(set(rule_filenames))
        logger.debug("Loaded %d rule files" % len(rule_filenames))

        # We load rules from each rule file here.
        rules = []
        for rule_filename in rule_filenames:
            try:
                rules += json.loads(sublime.load_resource(rule_filename))
            except Exception as msg:
                logger.warning("Error loading [%s]: %s" % (rule_filename, msg))
                if user_settings.get('debug', False):
                    sublime.error_message("Error loading [%s]" % rule_filename)

        # Now we load custom rules on top of this.
        try:
            for rule_filename in user_settings.get('custom_rules', []):
                try:
                    env_variables = sublime.active_window().extract_variables()
                    rule_filename = sublime.expand_variables(rule_filename,
                                                             env_variables)

                    with open(rule_filename, encoding='utf-8') as crf:
                        custom_rule = json.loads(crf.read())
                        rules += custom_rule
                except Exception as msg:
                    logger.warning("Error opening [%s]: %s" %
                                   (rule_filename, msg))
        except Exception as msg:
            logger.warning("Error opening custom rules: %s" % msg)

        if not user_settings:
            logger.warning("Settings not found, cannot load rules.")
            return False

        for rule_id in user_settings.get('suppress_rules', []):
            try:
                rules = filter(lambda s: s.get('id', '') != rule_id, rules)
            except Exception as msg:
                logger.warning("Error suppressing rules for %s: %s" %
                               (rule_id, msg))

        # Only include non-disabled rules -- if 'disabled' is not specified, assume False
        rules = list(filter(lambda x: not x.get('disabled', False), rules))

        # Filter by tags, if specified, convert all to lowercase
        show_only_tags = set([k.lower().strip()
                             for k in user_settings.get('show_only_tags', [])])
        if show_only_tags:
            def filter_func(x):
                return set([k.lower().strip()
                            for k in x.get('tags', [])]) & show_only_tags

            rules = list(filter(filter_func, rules))

        logger.debug("Loaded %d rules" % len(rules))

        return True

    def load_syntax_mapping(self):
        """Load syntax content from various installed packages."""
        global applies_to_ext_mapping, applies_to_ext_alias

        logger.debug('DevSkimEngine.load_syntax_mapping()')

        def _convert_mapping_to_sets():
            for k, v in applies_to_ext_mapping.items():
                applies_to_ext_mapping[k]['syntax'] = \
                    set(applies_to_ext_mapping[k]['syntax'])
                applies_to_ext_mapping[k]['extensions'] = \
                    set(applies_to_ext_mapping[k]['extensions'])

        _convert_mapping_to_sets()

        # Iterate through all syntax files
        for filename in sublime.find_resources("*.sublime-syntax"):
            # Load the contents
            syntax_file = sublime.load_resource(filename)
            logger.debug("Loading syntax: {0}".format(filename))

            applies_to_name = None

            # Look for all extensions
            in_file_extensions = False

            for line in syntax_file.splitlines():
                # Clean off whitepsace
                line = line.strip()

                name_match = re.match(r'name: (.*)', line)
                if name_match:
                    applies_to_name = name_match.group(1).replace("\"", "").lower().strip()
                    if applies_to_name not in applies_to_ext_mapping:
                        applies_to_ext_mapping[applies_to_name] = {
                            'syntax': set([filename]),
                            'extensions': set()
                        }
                    continue

                # Are we entering?
                if line == 'file_extensions:':
                    in_file_extensions = True
                    continue

                # Are we in the file extension section?
                if in_file_extensions:
                    if line.startswith('- '):
                        # Add the extension to the mapping
                        extension = line.replace("- ", "").strip()
                        logger.debug("Added additional extension: {0}".format(extension))
                        applies_to_ext_mapping[applies_to_name]['extensions'].add(extension)
                    else:
                        in_file_extensions = False
                        break

        _convert_mapping_to_sets()

        # Copy over alias'ed keys (e.g. "csharp" => "c#")
        for k, v in applies_to_ext_alias.items():
            if k not in applies_to_ext_mapping:
                applies_to_ext_mapping[k] = {
                    'syntax': set(),
                    'extensions': set()
                }
            applies_to_ext_mapping[k]['syntax'] |= applies_to_ext_mapping[v]['syntax']
            applies_to_ext_mapping[k]['extensions'] |= applies_to_ext_mapping[v]['extensions']


    def re_modifiers_to_flags(self, modifiers, default=re.IGNORECASE | re.MULTILINE):
        """Convert modifier flags from rules to a regex flag value."""
        flags = 0
        if modifiers:
            modifiers = map(lambda s: s.lower(), modifiers)

            # The rule here is that if a modifier is passed,
            # then that's the modifier used. Otherwise, we do
            # IGNORECASE | MULTILINE.
            if 'dotall' in modifiers:
                flags |= re.DOTALL
            if 'multiline' in modifiers:
                flags |= re.MULTILINE
            if 'ignorecase' in modifiers:
                flags |= re.IGNORECASE
        else:
            flags = default

        return flags

    def execute(self, file_contents, filename=None, extension=None, syntax=None,
                severities=None, force_analyze=False, offset=0):
        """Execute all of the rules against a given string of text."""
        global rules, applies_to_ext_mapping

        logger.debug("execute([len=%d], [name=%s], [ext=%s], [syntax=%s], [force=%s], [offset=%d])" %
                     (len(file_contents), filename, extension, syntax, force_analyze, offset))

        filename_basename = os.path.basename(filename).strip()

        if not file_contents:
            return []

        syntax_types = []   # Example: ["csharp"], from the file itself

        # TODO Cache this elsewhere, silly to do every time, I think.
        for k, v in applies_to_ext_mapping.items():
            if (syntax in v.get('syntax', []) or
                    extension in v.get('extensions', [])):
                k = k.replace("\"", "")     # Some names are quoted
                syntax_types.append(k)
        result_list = []
        syntax_types = list(set(syntax_types))

        logger.debug("Loaded syntax types: {0}".format(syntax_types))

        for rule in rules:
            logger.debug('Rule: {0}'.format(rule.get('id', None)))

            # Don't even scan for rules that we don't care about
            if not force_analyze and rule.get('severity', 'critical') not in severities:
                logger.debug("Ignoring rule [%s] due to severity." % rule.get('id', ''))
                continue

            # No syntax means "match any syntax"
            rule_applies_to = rule.get('applies_to', [])
            applies_to_check = any([fnmatch.fnmatch(filename_basename, glob_pattern) for glob_pattern in rule_applies_to])

            if (force_analyze or
                    not rule_applies_to or
                    applies_to_check or
                    set(rule_applies_to) & set(syntax_types) or
                    '.%s' % extension in rule_applies_to):

                for pattern_dict in rule['patterns']:
                    # Secondary applicability
                    pattern_applies_to = set(pattern_dict.get('applies_to', []))
                    if (pattern_applies_to and
                            not force_analyze and
                            not pattern_applies_to & set(syntax_types) and
                            not '.%s' % extension in pattern_applies_to):
                        logger.debug("Ignoring rule [%s], applicability check." % rule.get('id', ''))
                        continue

                    pattern_str = pattern_dict.get('pattern')

                    start = end = -1

                    orig_pattern_str = pattern_str

                    if pattern_dict.get('type') == 'substring':
                        pattern_str = re.escape(pattern_str)
                    elif pattern_dict.get('type') == 'string':
                        pattern_str = r'\b%s\b' % re.escape(pattern_str)
                    elif pattern_dict.get('type') == 'regex':
                        pass
                    elif pattern_dict.get('type') == 'regex-word':
                        pattern_str = r'\b%s\b' % pattern_str
                    else:
                        logger.warning("Invalid pattern type [%s] found." %
                                       pattern_dict.get('type'))
                        continue

                    scope_list = pattern_dict.get('subtype', [])

                    flags = self.re_modifiers_to_flags(pattern_dict.get('modifiers', []))

                    logger.debug('Searching for {0} in contents.'.format(pattern_str))

                    for match in re.finditer(pattern_str, file_contents, flags):

                        if not match:
                            logger.debug("re.finditer([%s], [%s]) => [-]" %
                                         (pattern_str, len(file_contents)))
                            continue        # Does this ever happen?

                        logger.debug("re.finditer([%s], [%s]) => [%d, %d]" %
                                     (pattern_str, len(file_contents),
                                      match.start(), match.end()))

                        start = match.start()
                        end = match.end()

                        # Check for per-row suppressions
                        row_number = self.view.rowcol(start)
                        line_list = [
                            self.view.substr(self.view.line(start))
                        ]
                        if row_number[0] > 0:   # Special case, ignore
                            prev_line = self.view.text_point(row_number[0] - 1, 0)
                            line_list.append(self.view.substr(self.view.line(prev_line)))

                        if self.is_suppressed(rule, line_list):
                            continue    # Don't add the result to the list

                        # If there are conditions, run them now
                        context = {
                            'filename': filename,
                            'file_contents': file_contents,
                            'rule': rule,
                            'pattern': pattern_dict
                        }

                        result_details = {
                            'rule': rule,
                            'match_content': match.group(),
                            'match_region': sublime.Region(start + offset, end + offset),
                            'match_start': start + offset,
                            'match_end': end + offset,
                            'pattern': orig_pattern_str,
                            'scope_list': scope_list
                        }

                        if self.meets_conditions(context, result_details):
                            result_list.append(result_details)
            else:
                logger.debug("Not running rule check [force={0}, rule_applies={1}, syntax={2}, ext={3},]".format(
                    force_analyze, rule_applies_to, set(rule_applies_to) & set(syntax_types), extension))

        return result_list

    def meets_conditions(self, context, result):
        """Checks to see if a finding meets specified conditions from the rule."""
        pattern = context.get('pattern')
        if not pattern:
            return True     # No pattern means same thing as them all passing.

        conditions = pattern.get('conditions')
        if not conditions:
            return True     # No conditions means same as them all passing.

        match_start = result.get('match_start')
        line = self.view.substr(self.view.line(match_start))

        if not line:
            logger.error('No line was found in meets_conditions')
            return True     # No line means something is broken

        logger.debug('Found %d conditions', len(conditions))

        cond_result = True

        for condition in conditions:
            name = condition.get('name', '').replace('-', '_')
            value = condition.get('value')
            invert = condition.get('invert', False)

            if name in conditional_func_map:
                kwargs = {
                    'view': self.view,
                    'line': line,
                    'value': value
                }
                kwargs.update(context)
                kwargs.update(result)

                r = conditional_func_map[name](**kwargs)
                cond_result &= not r if invert else r
            else:
                logger.warning('Invalid condition name: %s', name)

        return cond_result

    def severity_abbreviation(self, severity):
        """Convert a severity name into an abbreviation."""
        if severity is None:
            return ""
        severity = severity.strip().lower()

        if severity == "critical":
            return "crit"
        elif severity == "important":
            return "imp."
        elif severity == "moderate":
            return "mod."
        elif severity == "low":
            return "low"
        elif severity == "defense-in-depth":
            return "did."
        elif severity == "informational":
            return "info"
        elif severity == "manual-review":
            return "rvw."
        return ""

    def is_suppressed(self, rule, lines):
        """Should the result be suppressed based on the given rule and line content."""
        global user_settings

        if not rule or not lines:
            return False

        # Are suppression rules enabled at all?
        if not user_settings.get('allow_suppress_specific_rules') and not user_settings.get('allow_suppress_all_rules'):
            logger.debug('Suppression disabled via config, nothing to do.')
            return False

        for line in lines:
            line = line.lower()
            if 'devskim:' not in line:
                continue

            if user_settings.get('allow_suppress_specific_rules'):
                for match in re.finditer(r'ignore ([^\s]+)\s*(?!\s+until (\d{4}-\d{2}-\d{2}))', line):
                    if match.group(1).lower() == rule.get('id').lower():
                        suppress_until = match.group(2)
                        if suppress_until is None:
                            # Permanent suppression of this rule
                            return True
                        try:
                            suppress_until = datetime.datetime.strptime(suppress_until, '%Y-%m-%d')
                            if datetime.date.today() < suppress_until.date():
                                logger.debug('Ignoring rule [%s], limited suppression.', rule.get('id'))
                                return True
                        except Exception as msg:
                            logger.debug("Error parsing suppression date 1: %s", msg)

            if user_settings.get('allow_suppress_all_rules'):
                for match in re.finditer(r'ignore all\s*(?!\s+until (\d{4}-\d{2}-\d{2}))', line):
                    suppress_until = match.group(1)
                    if suppress_until is None:
                        # Permanent suppression of all rules
                        return True
                    try:
                        suppress_until = datetime.datetime.strptime(suppress_until, '%Y-%m-%d')
                        if datetime.date.today() < suppress_until.date():
                            logger.debug('Ignoring rule [%s] global suppression.', rule.get('id'))
                            return True
                    except Exception as msg:
                        logger.debug("Error parsing suppression date 2: %s", msg)

            if rule.get('severity') == 'manual-review':
                if re.search(r'reviewed ([^\s]+)\s*(?!\s+on \d{4}-\d{2}-\d{2})', line):
                    logger.debug('Ignoring rule [%s], manual review complete.', rule.get('id'))
                    return True

        return False

    def ds_show_popup(self, content, flags, location, max_width, max_height,
                      on_navigate=None, on_hide=None, repeat_duration_ms=50):
        """Delay-load a popup to give the UI time to get to the scrolled position."""
        if self.view.is_popup_visible():
            return  # OK, a popup is already being shown

        # Try to show the popup
        self.view.show_popup(content=content,
                             flags=flags,
                             location=location,
                             max_width=max_width,
                             max_height=max_height,
                             on_navigate=on_navigate,
                             on_hide=on_hide)

        # Retry in case we're scrolling
        sublime.set_timeout_async(lambda: self.ds_show_popup(content=content,
                                                             flags=flags,
                                                             location=location,
                                                             max_width=max_width,
                                                             max_height=max_height,
                                                             on_navigate=on_navigate,
                                                             on_hide=on_hide), repeat_duration_ms)

    def is_file_ignored(self, filename):
        """Check to see if a file (by filename) is ignored from analysis."""
        global user_settings

        if not filename:
            return False

        for ignore_pattern in user_settings.get('ignore_files', []):
            logger.warning("Checking {0}".format(ignore_pattern))
            if re.match(ignore_pattern, filename, re.IGNORECASE):
                return True

        if not user_settings.get('ignore_from_gitignore', True):
            return False

        try:
            if os.name == 'nt':
                # Only supported on Windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.SW_HIDE
            else:
                startupinfo = None
                creationflags = 0

            cwd = os.path.dirname(filename)
            filename = shlex.quote(filename)
            output = subprocess.check_output(["git", "check-ignore", "--no-index", filename],
                                             cwd=cwd, stderr=subprocess.STDOUT, shell=False,
                                             startupinfo=startupinfo,
                                             creationflags=creationflags)
            return filename in output.decode('utf-8')
        except subprocess.CalledProcessError as msg:
            # This is OK, just catching non-zero errorlevel
            return filename in msg.output.decode('utf-8')
        except Exception as msg:
            logger.warning("Error checking if file is ignored: %s", msg)

        return False

class ReplaceTextCommand(sublime_plugin.TextCommand):
    """Simple function to route text changes to view."""

    def run(self, edit, a, b, result):
        """Replace given text for a region in a view."""
        logger.debug("Replacing [%s] into region (%d, %d)" % (result, a, b))
        self.view.replace(edit, sublime.Region(a, b), result)


class InsertTextCommand(sublime_plugin.TextCommand):
    """Simple function to route text inserts to view."""

    def run(self, edit, a, result):
        """Insert given text for a region in a view."""
        self.view.insert(edit, a, result)


class DevSkimAnalyzeCommand(sublime_plugin.TextCommand):
    """Perform an ad-hoc analysis of the open file."""

    def run(self, edit_token, **args):
        """Execute the analysis."""
        global devskim_event_listener
        logger.debug("DevSkimAnalyzeCommand invoked.")

        if not devskim_event_listener:
            devskim_event_listener = DevSkimEventListener()
        try:
            show_popup = args.get('show_popup', True)
            devskim_event_listener.analyze_current_view(self.view, show_popup=show_popup)
        except Exception as msg:
            logger.warning("Error analyzing current view: %s" % msg)
            traceback.print_exc()


class DevSkimReloadRulesCommand(sublime_plugin.TextCommand):
    """Mark the DevSkim rules to be reloaded next time they're needed."""

    def run(self, text):
        """Execute the analysis."""
        global rules, stylesheet_content
        rules = []
        stylesheet_content = ""

def periodic_analysis_callback():
    try:
        view = sublime.active_window().active_view()
        view.run_command("dev_skim_analyze", args={'show_popup': False})
        frequency = sublime.load_settings('DevSkim.sublime-settings').get('show_highlights_on_time', 0)
        # Re-evaluate this so changes are picked up if the user changes their config.
        if frequency > 0:
            sublime.set_timeout_async(periodic_analysis_callback, frequency)

    except Exception as msg:
        print("Error: {0}".format(msg))

def plugin_loaded():
    """Handle the plugin_loaded event from ST3."""
    logger.info('DevSkim plugin_loaded(), Sublime Text v%s' % sublime.version())

    # Schedule analysis based on configuration
    frequency = sublime.load_settings('DevSkim.sublime-settings').get('show_highlights_on_time', 0)
    if frequency > 0:
        sublime.set_timeout_async(periodic_analysis_callback, frequency)

def plugin_unloaded():
    """Handle the plugin_unloaded event from ST3."""
    logger.info("DevSkim plugin_unloaded()")
