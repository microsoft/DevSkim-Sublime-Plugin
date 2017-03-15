DevSkim Plugin for Sublime Text
===============================

The plugin implements a security linter within the Sublime Text editor, leveraging the rules from the [DevSkim](https://github.com/Microsoft/DevSkim)
repository. It helps software engineers to write secure code by flagging potentially dangerous calls, and gives in-context advice for remediation.

### PUBLIC PREVIEW

DevSkim is currently in *public preview*. We're looking forward to working with the community
to improve both the scanning engines and rules over the next few months, and welcome your feedback
and contributions!

![DevSkim Demo](https://github.com/Microsoft/DevSkim-Sublime-Plugin/raw/master/doc/DevSkim-Sublime-Demo-1.gif)

Requirements
--------------

The plugin requires Sublime Text 3 (build >= 3114), and will function on Windows, Linux, and MacOS.

Installation
------------

Install this plugin using [Package Control](https://packagecontrol.io/) from Sublime Text. The package name
is `DevSkim`.

Alternatively, you can clone this repository into your Sublime Text "Packages" folder. For example, under Windows:

```
cd "%APPDATA%\"Sublime Text 3\Packages"
git clone https://github.com/Microsoft/DevSkim-Sublime-Plugin.git DevSkim
```

MacOS:
```
cd ~/"Library/Application Support/Sublime Text 3/Packages"
git clone https://github.com/Microsoft/DevSkim-Sublime-Plugin.git DevSkim
```

Linux:
```
cd ~/.config/sublime-text-3/Packages
git clone https://github.com/Microsoft/DevSkim-Sublime-Plugin.git DevSkim
```

Note if you are using the portable version of Sublime Text, the location will be different. See the
[Sublime Text documentation](http://docs.sublimetext.info/en/latest/basic_concepts.html#the-data-directory) for more information.

**IMPORTANT** If you already have a package called `DevSkim` installed, either remove this first, or clone this repo to a different folder.

Using DevSkim
-------------

By default, DevSkim will run as you type, highlighting code that fails a rule. If you click on a highlighted bit of code, you will
see the rule in the status bar.

You can run a full scan by pressing Ctrl-Shift-g, which will result in a popup showing all findings for the file. You can also choose
`DevSkim: Analyze File` from the Command Palette.

Platform support
----------------

#### Operating System:

The plugin has identical behavior across Windows, MacOS, and Linux.

#### Sublime Text Version:

The plugin requires [Sublime Text 3](http://www.sublimetext.com/3) builds >= 3114.

Settings
--------
You can customize how DevSkim works through the `Settings -- User` menu item.
If you change any settings, you should reload the DevSkim configuration, either
by restarting Sublime Text or by running the command `DevSkim: Reload Configuration`.

Rules System
------------

The plugin supports both built-in and custom rules:

#### Built-In Rules

Built-in rules come from the [DevSkim](https://github.com/Microsoft/DevSkim) repository, and should be stored
in the `DevSkim-Common/rules` directory within the DevSkim package directory.

Rules are organized by subdirectory and file, but are flattened internally when loaded.

Each rule contains a set of patterns (strings and regular expressions) to match, a list of file types to
apply the rule to, and, optionally, a list of possible code fixes.

Information how writing rules can be found at
[Writing-Rules](https://github.com/Microsoft/DevSkim/wiki/Writing-Rules)

Reporting Issues
----------------
Please see [CONTRIBUTING](https://github.com/Microsoft/DevSkim-Sublime-Plugin/blob/master/CONTRIBUTING.md) for information on reporting issues and contributing code.

Tips and Known Issues
---------------------
See tips and known issues in the [wiki page](https://github.com/Microsoft/DevSkim-Sublime-Plugin/wiki/Tips-and-Known-Issues).
