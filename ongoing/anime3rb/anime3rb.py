import re
import json
from bs4 import BeautifulSoup

class Anime3rb_utils:
    def parse_search_result(text):
        links = []
        soup = BeautifulSoup(text, "html.parser")
        titles = soup.find_all("h2", class_="pt-1 text-[1.06rem] text-ellipsis whitespace-nowrap overflow-hidden rtl:text-right")
        for j in range(len(titles)):
            name = titles[j].get_text().replace(" ", "-").replace(":", "-").replace("--", "-").lower() # nic ecode
            links.append(f"https://anime3rb.com/titles/{name}")
        return titles, links

class Anime3rb_downloader:
    def __init__(self, session):
        self.session = session
    def search(self, query):
        '''検索結果を返すコード'''
        try:
            metadata_response = self.session.get("https://anime3rb.com/search", params={ "q": query })
                        
            result, links = Anime3rb_utils.parse_search_result(metadata_response.text)
            
            return result, links
            
        except Exception as e:
            print(e)
            return None     
    def get_info(self, url):
        '''infoを返すコード'''
        try:
            metadata_response = self.session.get(url)
                        
            soup = BeautifulSoup(metadata_response.text, 'html.parser')
            
            result = soup.find('span', {'dir': 'ltr'})
            h2_tags = soup.find_all('h2', class_='rounded')
            
            if result:
                en_title = result.get_text()
            jp_title = None
            for tag in h2_tags:
                if re.search(r'[\u3040-\u30FF\u4E00-\u9FFF]', tag.get_text()):
                    jp_title = tag.get_text()
                    break
            
            if jp_title:
                pass
            
            return [en_title,jp_title], url
            
        except Exception as e:
            print(e)
            return None     
    def get_player_info(self, url):
        '''playerの情報を返すコード'''
        try:
            metadata_response = self.session.get(url)
                        
            soup = BeautifulSoup(metadata_response.text, 'html.parser')
            
            section_tag = soup.find('section', id='player-section')
            x_data_content = section_tag.get('x-data', '')
            
            match = re.search(r"videoSource:\s*'([^']+)'", x_data_content)
            if match:
                video_source = match.group(1).replace('\\/', '/') 
                return video_source
            
        except Exception as e:
            print(e)
            return None     
    def get_player_meta(self, url):
        '''メタデータを殴って返します。'''
        try:
            metadata_response = self.session.get(url)
                        
            # BeautifulSoupでHTMLを解析
            soup = BeautifulSoup(metadata_response.text, "lxml")
            
            # <script>タグの中のJavaScriptを検索
            scripts = soup.find_all("script")
            videos_data = None
            
            for script in scripts:
                if script.string and "var videos =" in script.string:
                    # "var videos =" が含まれるスクリプトを抽出
                    js_code = script.string
                    # 正規表現でvideosの内容を抽出
                    match = re.search(r"var videos = (\[.*?\]);", js_code, re.DOTALL)
                    if match:
                        videos_data = match.group(1)
                        break
            

            if videos_data:
                # JSON形式を修正
                videos_data = re.sub(r"(\w+):", r'"\1":', videos_data)  # キーにダブルクォートを追加
                videos_data = videos_data.replace("'", '"')  # シングルクォートをダブルクォートに変換
                videos_data = re.sub(r'"https"://', r'https://', videos_data)  # "https":// を https:// に修正
                videos_data = re.sub(r",\s*]", "]", videos_data)  # 配列末尾の余分なカンマを削除
                
                print(videos_data)
            
                # JSONとしてロードして[{label, src}]の形に変換
                videos = json.loads(videos_data)
                result = [{"label": video["label"], "src": video["src"]} for video in videos]
                print(result)
            else:
                print("videosデータが見つかりませんでした。")
            
        except Exception as e:
            print(e)
            return None  