# Regular Expression Cheat Sheets and Resources
- [ Regular Expression Cheat Sheet](https://web.mit.edu/hackl/www/lab/turkshop/slides/regex-cheatsheet.pdf)
- [Quick-Start: Regex Cheat Sheet](https://www.rexegg.com/regex-quickstart.html)
- [RegexR - Generate Regular Expressions](https://regexr.com)
- [RegexOne Exercises](https://regexone.com)
- [Regex Crossword](https://regexcrossword.com)
- [Regex101](https://regex101.com/)

## Quick Regex Reference

<table border="1" cellspacing="0" cellpadding="8">
<tbody>
<tr>
<th>Character</th>
<th>Meaning</th>
<th>Example</th>
</tr>
<tr>
<td class="sc">*</td>
<td>Match&nbsp;<strong>zero, one or more</strong>&nbsp;of the previous</td>
<td><code>Ah*</code>&nbsp;matches "<code>Ahhhhh</code>" or "<code>A</code>"</td>
</tr>
<tr>
<td class="sc">?</td>
<td>Match&nbsp;<strong>zero or one</strong>&nbsp;of the previous</td>
<td><code>Ah?</code>&nbsp;matches "<code>Al</code>" or "<code>Ah</code>"</td>
</tr>
<tr>
<td class="sc">+</td>
<td>Match&nbsp;<strong>one or more</strong>&nbsp;of the previous</td>
<td><code>Ah+</code>&nbsp;matches "<code>Ah</code>" or "<code>Ahhh</code>" but not "<code>A</code>"</td>
</tr>
<tr>
<td class="sc">\</td>
<td>Used to&nbsp;<strong>escape</strong>&nbsp;a special character</td>
<td><code>Hungry\?</code>&nbsp;matches "<code>Hungry?</code>"</td>
</tr>
<tr>
<td class="sc">.</td>
<td>Wildcard character, matches&nbsp;<strong>any</strong>&nbsp;character</td>
<td><code>do.*</code>&nbsp;matches "<code>dog</code>", "<code>door</code>", "<code>dot</code>", etc.</td>
</tr>
<tr>
<td class="sc">( )</td>
<td><strong>Group</strong>&nbsp;characters</td>
<td>See example for&nbsp;<code>|</code></td>
</tr>
<tr>
<td class="sc">[ ]</td>
<td>Matches a&nbsp;<strong>range</strong>&nbsp;of characters</td>
<td><code>[cbf]ar</code>&nbsp;matches "car", "bar", or "far"<br /><code>[0-9]+</code>&nbsp;matches any positive integer<br /><code>[a-zA-Z]</code>&nbsp;matches ascii letters a-z (uppercase and lower case)<br /><code>[^0-9]</code>&nbsp;matches any character not 0-9.</td>
</tr>
<tr>
<td class="sc">|</td>
<td>Matche previous&nbsp;<strong>OR</strong>&nbsp;next character/group</td>
<td><code>(Mon|Tues)day</code>&nbsp;matches "Monday" or "Tuesday"</td>
</tr>
<tr>
<td class="sc">{ }</td>
<td>Matches a specified&nbsp;<strong>number of occurrences</strong>&nbsp;of the previous</td>
<td><code>[0-9]{3}</code>&nbsp;matches "315" but not "31"<br /><code>[0-9]{2,4}</code>&nbsp;matches "12", "123", and "1234"<br /><code>[0-9]{2,}</code>&nbsp;matches "1234567..."</td>
</tr>
<tr>
<td class="sc">^</td>
<td><strong>Beginning</strong>&nbsp;of a string. Or within a character range&nbsp;<code>[]</code>&nbsp;negation.</td>
<td><code>^http</code>&nbsp;matches strings that begin with http, such as a url.<br /><code>[^0-9]</code>&nbsp;matches any character not 0-9.</td>
</tr>
<tr>
<td class="sc">$</td>
<td><strong>End</strong>&nbsp;of a string.</td>
<td><code>ing$</code>&nbsp;matches "exciting" but not "ingenious"</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
