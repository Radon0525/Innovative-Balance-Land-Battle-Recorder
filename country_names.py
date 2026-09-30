"""Readable country tags; unknown or modded tags remain visible without guessing."""
NAMES={'GER':'ドイツ','SOV':'ソ連','JAP':'日本','USA':'アメリカ','ENG':'イギリス','FRA':'フランス',
       'ITA':'イタリア','CHI':'中国','PRC':'中国共産党','POL':'ポーランド','FIN':'フィンランド',
       'ROM':'ルーマニア','HUN':'ハンガリー','CAN':'カナダ','AST':'オーストラリア','RAJ':'英領インド'}
def country_name(country=None,tag=None):
    if tag:return f'{NAMES[tag]} ({tag})' if tag in NAMES else tag
    return f'国 #{country}' if country and country>0 else '所属不明'
