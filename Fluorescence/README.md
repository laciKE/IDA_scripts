# Fluorescence

Call Highlighter

Inspired by [https://github.com/tacnetsol/ida/blob/master/plugins/fluorescence/fluorescence.py](https://github.com/tacnetsol/ida/blob/master/plugins/fluorescence/fluorescence.py)

Few weeks ago I saw somewhere on the Internet question about IDA Freeware compatibility with the Fluorescence plugin. And because this plugin is written in IDAPython and IDAPython isn't officially supported by IDA Freeware, also this plugin isn't compatible.

However, when I checked what this plugin does, it turns out that it is very simple - its purpose is to highlight call instructions. So as an exercise I re-created IDC script with similar feature, and moreover, I also created plugin version of IDC Fluorescence. Actually, this is my first IDC plugin (yes, real plugin)

## Features
* simple IDC script and/or plugin for highlighting call-like instructions
* currently supported calls and and push+rets instruction
* prints list of all found calls and basic stats
* re-run again for unhighlighting

![Highlighted calls]screenshot_1.png)

![Basic stats]screenshot_2.png)

## Installation and usage

* plugin:
	* copy file 'FLuorescence.idc' into the '%IDAHOME%\plugins' directory
	* run plugin in IDA via **Edit->Plugins->Fluorescence** Menu entry
* script:
	* if you do not want plugin, but simple IDC script instead, just run the 'Fluorescence_script.idc' file in IDA with **File->Script File**

