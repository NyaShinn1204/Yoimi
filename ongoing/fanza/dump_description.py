import json
from bs4 import BeautifulSoup

html = """
<script type="application/ld+json">
{"@context":"http://schema.org", "@type":"Product", "name":"新人 めっちゃ性格の良い方言美少女AV DEBUT 石原希望", "image":"https://pics.dmm.co.jp/digital/video/mifd00117/mifd00117ps.jpg", "description":"少し方言訛りの残る19歳美少女を奇跡の発掘！！池●エ●●ザに似ていると言われる目鼻立ちの整った彼女は、得意な一輪車に乗って登場（笑）めっちゃ明るい性格だけど、初脱ぎでは恥ずかしそうに照れ笑い。桜色の乳首に柔らかそうなFカップ美巨乳！昔の彼氏仕込みというフェラを嬉しそうに披露してくれたり、童貞くん相手には意外なお姉さんっぷりを見せたり、クルクルいろんな表情を見せてくれる新世代美少女、AVデビュー！", "sku":"mifd00117", "brand":{"@type":"Brand", "name":"ムーディーズ"}, "subjectOf":{"@type":"VideoObject", "name":"新人 めっちゃ性格の良い方言美少女AV DEBUT 石原希望", "description":"少し方言訛りの残る19歳美少女を奇跡の発掘！！池●エ●●ザに似ていると言われる目鼻立ちの整った彼女は、得意な一輪車に乗って登場（笑）めっちゃ明るい性格だけど、初脱ぎでは恥ずかしそうに照れ笑い。桜色の乳首に柔らかそうなFカップ美巨乳！昔の彼氏仕込みというフェラを嬉しそうに披露してくれたり、童貞くん相手には意外なお姉さんっぷりを見せたり、クルクルいろんな表情を見せてくれる新世代美少女、AVデビュー！", "contentUrl":"https://cc3001.dmm.co.jp/litevideo/freepv/m/mif/mifd00117/mifd00117_sm_w.mp4", "thumbnailUrl":"https://pics.dmm.co.jp/digital/video/mifd00117/mifd00117jp-4.jpg", "uploadDate":"2020-05-01", "actor":{"@type":"Person", "name":"石原希望", "alternateName":"いしはらのぞみ"}, "genre":["美乳", "童貞", "フェラ", "美少女", "デジモ", "デビュー作品", "独占配信", "ハイビジョン", "単体作品"]}, "offers":{"@type":"Offer", "availability":"https://schema.org/InStock", "priceCurrency":"JPY", "price":"300"}, "aggregateRating":{"@type":"AggregateRating", "ratingValue":"4.03", "ratingCount":"593"}}
</script>
"""

# BeautifulSoupでHTMLを解析
soup = BeautifulSoup(html, "lxml")

# JSON-LDスクリプトを取得
script_tag = soup.find("script", {"type": "application/ld+json"})

if script_tag:
    try:
        # JSONをパース
        json_data = json.loads(script_tag.string)
        # descriptionを取得
        description = json_data.get("description", "No description found")
        print(description)
    except json.JSONDecodeError:
        print("Invalid JSON format")
else:
    print("No JSON-LD script found")
