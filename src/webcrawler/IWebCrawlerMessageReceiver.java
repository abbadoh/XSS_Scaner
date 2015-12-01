package webcrawler;

import java.net.URL;

public interface IWebCrawlerMessageReceiver {
    public void onWebCrawlerMessageReceived(URL message);
}
