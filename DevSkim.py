"""
Copyright (c) 2016 Microsoft. All rights reserved.
Licensed under the MIT License. See LICENSE.txt in the project root for license information.

DevSkim Sublime Text Plugin
https://github.com/Microsoft/DevSkim-Sublime-Plugin
"""

import datetime
import json
import logging
import re
import time
import os
import traceback
import webbrowser

try:
    import sublime
    import sublime_plugin
except:
    print("Unable to import Sublime Text modules. DevSkim must be run within Sublime Text.")
    import sys
    sys.exit(1)

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
    "csharp": {
        "syntax": ["Packages/C#/C#.sublime-syntax"],
        "extensions": ["cs"]
    },
    "aspnet": {
        "syntax": [],
        "extensions": ["aspx"]
    },
    "python": {
        "syntax": ["Packages/Python/Python.sublime-syntax"],
        "extensions": ["py"]
    },
    "c": {
        "syntax": ["Packages/C++/C.sublime-syntax"],
        "extensions": ["c", "h"]
    },
    "cpp": {
        "syntax": ["Packages/C++/C++.sublime-syntax"],
        "extensions": ["c", "h", "cpp", "hpp"]
    },
    "javascript": {
        "syntax": ["Packages/JavaScript/JavaScript.sublime-syntax"],
        "extensions": ["js"]
    },
    "ruby": {
        "syntax": ["Packages/Ruby/Ruby.sublime-syntax"],
        "extensions": ["rb", "erb"]
    },
    "java": {
        "syntax": ["Packages/Java/Java.sublime-syntax"],
        "extensions": ["java"]
    },
    "php": {
        "syntax": ["Packages/PHP/PHP.sublime-syntax"],
        "extensions": ["php"]
    },
    "objective-c": {
        "syntax": ["Packages/Objective-C/Objective-C.sublime-syntax"],
        "extensions": ["m", "mm", "h", "c"]
    },
    "ios": {
        "syntax": ["Packages/Objective-C/Objective-C.sublime-syntax"],
        "extensions": ["m", "mm", "h", "c"]
    },
    "swift": {
        "syntax": ["Packages/Swift/Swift.sublime-syntax"],
        "extensions": ["swift"]
    },
    "java": {
        "syntax": ["Packages/Java/Java.sublime-syntax"],
        "extensions": ["java"]
    },
    "powershell": {
        "syntax": ["Packages/PowerShell/PowerShell.sublime-syntax"],
        "extensions": ["ps1"]
    },
    "swift": {
        "syntax": ["Packages/Swift/Swift.sublime-syntax"],
        "extensions": ["swift"]
    }
}

# Currently marked regions
marked_regions = []

# Cached stylesheet content
stylesheet_content = ""

# Cache suppress days
suppress_days = []

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
        self.lazy_initialize()

        # logger.debug("on_selection_modified()")

        global marked_regions, finding_list

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

        # Special commands, intercept and perform the fix
        if command.startswith('#fixit'):
            rule_id, fixid = command.split(',')[1:]
            fixid = int(fixid)

            for finding in finding_list:
                rule = finding.get('rule')

                if rule.get('id') == rule_id:

                    region_start = finding.get("match_region").begin()
                    contents = self.view.substr(self.view.line(region_start))

                    fixit = rule.get('fix_it')
                    if not fixit or fixid >= len(fixit):
                        continue

                    fixit = fixit[fixid]
                    if fixit['type'] == 'regex_substitute':
                        search = fixit['search']
                        replace = fixit['replace']
                        for k in range(1, 9):
                            replace = replace.replace("${0}".format(k), "\\{0}".format(k))
                        result = re.sub(search, replace, contents, flags=re.IGNORECASE)
                        logger.debug("Result of search/replace was [%s]", result)
                        self.view.run_command('replace_text', {
                            'a': self.view.line(region_start).a,
                            'b': self.view.line(region_start).b,
                            'result': result
                        })

                    self.view.hide_popup()

                    # Only fix once
                    break
        elif command.startswith('#add-reviewed'):
            rule_id, region_start = command.split(',')[1:]
            cur_line = self.view.line(int(region_start))

            comment = "  DevSkim: reviewed %s on %s " % (rule_id, datetime.datetime.now().strftime("%Y-%m-%d"))
            username = user_settings.get('manual_reviewer_name', '')
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

            if suppress_day == -1:
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
        self.lazy_initialize()

        if user_settings.get('show_highlights_on_modified', False):
            try:
                self.analyze_current_view(view, show_popup=False, single_line=True)
            except Exception as msg:
                logger.warning("Error analyzing current view: %s", msg)

    def on_load_async(self, view):
        """Handle asynchronous loading event."""
        global user_settings
        self.lazy_initialize()

        if user_settings.get('show_highlights_on_load', False):
            try:
                self.analyze_current_view(view, show_popup=False)
            except Exception as msg:
                logger.warning("Error analyzing current view: %s", msg)

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

    def analyze_current_view(self, view, show_popup=True, single_line=False):
        """Kick off the analysis."""
        global marked_regions, finding_list, user_settings

        if view is None or view.window() is None:
            # Early abort if we don't have a View and Window
            return

        window = view.window()

        self.lazy_initialize()

        logger.debug("analyze_current_view()")

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
            result_list = self.execute(file_contents, extension, syntax, show_severity, force_analyze, offset)
            logger.debug("DevSkim retured: [%s]", result_list)
        except Exception as ex:
            logger.warning("Error executing DevSkim: [%s]", ex)
            traceback.print_exc()

        # rule['overrides'] logic
        overrides_list = []

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
                         (original_result_list_count, len(result_list)))

        for result in result_list:
            # Narrow down to just the matching part of the line
            scope_name = view.scope_name(result.get('match_region').begin())

            scope_list = ["%s." % s for s in result.get('scope_list')]
            logger.debug("Current Scope: [%s], Applies to: %s" % (scope_name, scope_list))

            # Don't actually include if we're in a comment, or a quoted string, etc.
            if any([x in scope_name for x in scope_list]) or len(scope_list) == 0:
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
        sort_by = user_settings.get('sort_results_by', 'line_number')
        if sort_by == 'severity':
            finding_list.sort(key=lambda s: SEVERITY_LIST.index(s.get('rule').get('severity')))
        elif sort_by == 'line_number':
            finding_list.sort(key=lambda s: view.rowcol(s.get('match_region').begin())[0])

        for finding in finding_list:
            rule = finding.get('rule')
            region_start = finding.get("match_region").begin()
            region = view.rowcol(region_start)
            severity = rule.get('severity', 'informational')
            severity = self.severity_abbreviation(severity).upper()

            shown_finding_list.append([rule.get("name"), "%d: [%s] %s" %
                                       (region[0] + 1, severity,
                                       view.substr(view.line(region_start)).strip())])

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
                guidance.append('<li>Auto-Fix: <a href="#fixit,%s,%d">%s</a></li>' %
                                (rule.get('id'), fixid, fix.get('name')))
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

        # Only include active rules
        rules = list(filter(lambda x: x.get('active', True), rules))

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
        global applies_to_ext_mapping

        logger.debug('DevSkimEngine.load_syntax_mapping()')

        for k, v in applies_to_ext_mapping.items():
            applies_to_ext_mapping[k]['syntax'] = \
                set(applies_to_ext_mapping[k]['syntax'])
            applies_to_ext_mapping[k]['extensions'] = \
                set(applies_to_ext_mapping[k]['extensions'])

        # Iterate through all syntax files
        for filename in sublime.find_resources("*.sublime-syntax"):
            # Load the contents
            syntax_file = sublime.load_resource(filename)

            applies_to_name = None
            for k, v in applies_to_ext_mapping.items():
                for syntax in v.get('syntax', []):
                    if syntax == filename:
                        applies_to_name = k
                        break

            if not applies_to_name:
                continue        # We need to have these defined first.

            # Look for all extensions
            in_file_extensions = False

            for line in syntax_file.splitlines():
                # Clean off wittepsace
                line = line.strip()

                # Are we entering?
                if line == 'file_extensions:':
                    in_file_extensions = True
                    continue

                # Are we in the file extension section?
                if in_file_extensions:
                    if line.startswith('- '):
                        # Add the extension to the mapping
                        extension = line.replace("- ", "").strip()
                        applies_to_ext_mapping[applies_to_name]['extensions'].add(extension)
                    else:
                        in_file_extensions = False
                        break

    def execute(self, file_contents, extension=None, syntax=None,
                severities=None, force_analyze=False, offset=0):
        """Execute all of the rules against a given string of text."""
        global rules, applies_to_ext_mapping

        logger.debug("execute([len=%d], [%s], [%s], [%s], [%d]" %
                     (len(file_contents), extension, syntax, force_analyze, offset))

        if not file_contents:
            return []

        syntax_types = set([])   # Example: ["csharp"], from the file itself

        # TODO Cache this elsewhere, silly to do every time, I think.
        for k, v in applies_to_ext_mapping.items():
            if (v.get('syntax', None) == syntax or
                    extension in v.get('extensions', [])):
                syntax_types.add(k)
        result_list = []

        for rule in rules:

            # Don't even scan for rules that we don't care about
            if not force_analyze and rule.get('severity', 'critical') not in severities:
                logger.debug("Ignoring rule [%s] due to severity." % rule.get('id', ''))
                continue

            # No syntax means "match any syntax"
            rule_applies_to = rule.get('applies_to', [])
            if (force_analyze or
                    not rule_applies_to or
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
                    elif pattern_dict.get('type') == 'regex_word':
                        pattern_str = r'\b%s\b' % pattern_str
                    else:
                        logger.warning("Invalid pattern type [%s] found." %
                                       pattern_dict.get('type'))
                        continue

                    scope_list = pattern_dict.get('subtype', [])

                    modifiers = pattern_dict.get('modifiers', [])
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
                        # Default
                        flags = re.IGNORECASE | re.MULTILINE

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

                        result_list.append({
                            'rule': rule,
                            'match_content': match.group(),
                            'match_region': sublime.Region(start + offset, end + offset),
                            'match_start': start + offset,
                            'match_end': end + offset,
                            'pattern': orig_pattern_str,
                            'scope_list': scope_list
                        })

        return result_list

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
                for match in re.finditer(r'ignore ([^\s]+)\s+until (\d{4}-\d{2}-\d{2})', line):
                    if match.group(1) in ['all', rule.get('id', 'all').lower()]:
                        suppress_until = match.group(2)
                        try:
                            suppress_until = datetime.datetime.strptime(suppress_until, '%Y-%m-%d')
                            if datetime.date.today() < suppress_until.date():
                                logger.debug('Ignoring rule [%s] due to limited suppression.', rule.get('id'))
                                return True
                        except Exception as msg:
                            logger.debug("Error parsing suppression date: %s", msg)

            if not user_settings.get('allow_suppress_all_rules'):
                for match in re.finditer(r'ignore ([^\s]+)\s*(?!\s+until \d{4}-\d{2}-\d{2})', line):
                    if match.group(1) in ['all', rule.get('id', 'all').lower()]:
                        logger.debug('Ignoring rule [%s] due to unlimited suppression.', rule.get('id'))
                        return True

            if rule.get('severity') == 'manual-review':
                if re.search(r'reviewed ([^\s]+)\s*(?!\s+on \d{4}-\d{2}-\d{2})', line):
                    logger.debug('Ignoring rule [%s] due to manual review complete.', rule.get('id'))
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

    def run(self, text):
        """Execute the analysis."""
        global devskim_event_listener
        if not devskim_event_listener:
            devskim_event_listener = DevSkimEventListener()
        try:
            devskim_event_listener.analyze_current_view(self.view)
        except Exception as msg:
            logger.warning("Error analyzing current view: %s" % msg)


class DevSkimReloadRulesCommand(sublime_plugin.TextCommand):
    """Mark the DevSkim rules to be reloaded next time they're needed."""

    def run(self, text):
        """Execute the analysis."""
        global rules, stylesheet_content
        rules = []
        stylesheet_content = ""


def plugin_loaded():
    """Handle the plugin_loaded event from ST3."""
    logger.info('DevSkim plugin_loaded(), Sublime Text v%s' % sublime.version())


def plugin_unloaded():
    """Handle the plugin_unloaded event from ST3."""
    logger.info("DevSkim plugin_unloaded()")
