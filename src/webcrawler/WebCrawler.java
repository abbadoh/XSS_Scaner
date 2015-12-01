package webcrawler;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import xss_scanner.XssScanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WebCrawler {
    private Set<URL> processedUrls = new HashSet<URL>();
    private Set<String> permittedHosts = new HashSet<String>();
    private IWebCrawlerMessageReceiver receiver;
    private Map<String, String> cookies;

    public WebCrawler(IWebCrawlerMessageReceiver receiver, Map<String, String> cookies) {
        if (receiver != null) {
            this.receiver = receiver;
        }

        this.cookies = cookies;
    }

    public WebCrawler() {
        this(null, new HashMap<String, String>());
    }

    public void addPermittedHost(URL url) {
        final String allowedPrefix = "www.";
        String host = url.getHost();

        if (host.startsWith(allowedPrefix)) {
            host = host.substring(allowedPrefix.length());
        }

        permittedHosts.add(host);
        permittedHosts.add(allowedPrefix + host);
    }

    public Set<URL> findURLs(URL url) {
        processedUrls.clear();
        processURL(url);

        return processedUrls;
    }

    private void processURL(URL url) {

        if(Thread.currentThread().isInterrupted()) {
            return;
        }

        if (processedUrls.contains(url)) {
            return;
        }

        if (!permittedHosts.contains(url.getHost())) {
            return;
        }

        receiver.onWebCrawlerMessageReceived(url);

        processedUrls.add(url);

        String response = requestURL(url);

        if (response == null) {
            return;
        }

        Set<String> hrefs = findHrefs(response);

        for (String href : hrefs) {
            URL urlToProcess = hrefToURL(url, href);

            if (urlToProcess != null) {
                processURL(urlToProcess);
            }
        }
    }

    private URL hrefToURL(URL baseURL, String href) {
        URL url = null;

        try {
            url = new URL(href);
        } catch (MalformedURLException e1) {
            try {
                url = new URL(baseURL, href);
            } catch (MalformedURLException e2) {
                e2.printStackTrace();
            }
        }

        return url;
    }

    private Set<String> findHrefs(String html) {
        Set<String> urls = new HashSet<String>();

        Pattern anchorPattern = Pattern.compile("(?i)<a(?<attributes>[^>]+)>");
        Matcher anchorMatcher = anchorPattern.matcher(html);

        while (anchorMatcher.find()) {
            String attributes = anchorMatcher.group("attributes");

            Pattern hrefPattern = Pattern
                    .compile("(?i)href\\s*=\\s*((\\\"(?<href1>[^\"]*)\\\")|('(?<href2>[^']*)')|(?<href3>[^'\">\\s]+))");
            Matcher hrefMatcher = hrefPattern.matcher(attributes);

            String href;

            if (!hrefMatcher.find()) {
                continue;
            }

            if (hrefMatcher.group("href1") != null) {
                href = hrefMatcher.group("href1");
            } else if (hrefMatcher.group("href2") != null) {
                href = hrefMatcher.group("href2");
            } else if (hrefMatcher.group("href3") != null) {
                href = hrefMatcher.group("href3");
            } else {
                continue;
            }

            int sharpIndex = href.indexOf("#");

            if (sharpIndex != -1) {
                href = href.substring(0, sharpIndex);
            }

            if (href.isEmpty()) {
                continue;
            }
            if(isData(href)) {
                continue;
            }
            urls.add(href);
        }

        return urls;
    }

    private boolean isData(String href ) {
        return (href.endsWith(".gif") || href.endsWith(".jpg") || href.endsWith(".3gp") || href.startsWith("javascript")
                || href.endsWith(".rar") || href.endsWith(".zip") || href.endsWith(".7z"));
    }

    private Connection getConnection(URL url) {
        Connection connection = Jsoup.connect(url.toString());

        for (String name : cookies.keySet()) {
            connection = connection.cookie(name, cookies.get(name));
        }

        return connection;
    }

    private String requestURL(URL url) {
        try {
            return getConnection(url).get().toString();
        } catch (IOException e) {
            return null;
        }

    }
}
