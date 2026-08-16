# ATSGuard recall / false-negative report

attack corpus: 80 malicious cases

- caught (FLAG or BLOCK): 79/80  -> **recall 98.8%**
- blocked (BLOCK):        41/80  (51.2%)
- MISSED (ALLOW = false negative): 1/80  (**FN rate 1.2%**)

## recall by evasion technique
- synonym       : 7/8 caught (88%)
- plain         : 8/8 caught (100%)
- zero_width    : 8/8 caught (100%)
- homoglyph     : 8/8 caught (100%)
- fullwidth     : 8/8 caught (100%)
- bidi          : 8/8 caught (100%)
- tag_chars     : 8/8 caught (100%)
- leetspeak     : 8/8 caught (100%)
- char_spacing  : 8/8 caught (100%)
- white_text    : 4/4 caught (100%)
- tiny_font     : 4/4 caught (100%)

## recall by payload family
- superlative : 8/9 caught (89%)
- ignore      : 13/13 caught (100%)
- advance     : 13/13 caught (100%)
- rank        : 9/9 caught (100%)
- recommend   : 9/9 caught (100%)
- suppress    : 9/9 caught (100%)
- role        : 9/9 caught (100%)
- endmarker   : 9/9 caught (100%)

## misses (false negatives)
- superlative:synonym
