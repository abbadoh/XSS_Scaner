package xss_scanner;


import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class XssScanner implements IXssScanner {

    private final String DUMMY_CLASS_NAME = "TotallyNotHarmfulDevelopersDiv";
    private final String IMG_CLASS_NAME = "TotallyNotHarmfulDevelopersImg";
    private final String hackersHost = "http://xss.cgaming.org/";
    private URL host;
    private Queue<URL> processingUrls;
    private Set<URL> dummyVulnerableUrls;
    private Set<URL> imageVulnerableUrls;
    private IXssScannerMessageReceiver receiver;
    private Map<Integer, URL> injectedIdToUrl;
    private boolean isWorking;
    private Map<String, String> cookies;


    public XssScanner(IXssScannerMessageReceiver receiver, String host, Map<String, String> cookies) {
        this.receiver = receiver;
        this.cookies = cookies;
        isWorking = true;
        processingUrls = new LinkedBlockingQueue<URL>();
        dummyVulnerableUrls = new HashSet<URL>();
        imageVulnerableUrls = new HashSet<URL>();
        injectedIdToUrl = new HashMap<Integer, URL>();

        try {
            this.host = new URL(host);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        while (true) {

            if(Thread.currentThread().isInterrupted()) {
                return;
            }

            if(!processingUrls.isEmpty()) {
               processUrl(processingUrls.poll());
            }
            else {
                if(!isWorking) {
                    checkForInjections();
                    receiver.onScanFinished(dummyVulnerableUrls, imageVulnerableUrls);
                    return;
                }
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void processUrl(URL url) {
        injectedIdToUrl.put(createId(url), url);
        injectPayload(url, dummyPayload(url));
        injectPayload(url, injectImagePayload(url));
    }

    private void checkForInjections() {
        checkForDummyInjection();
        checkForImgInjection();
    }

    private String dummyPayload(URL url){
        return "<script>document.body.innerHTML += '<div style=\"display: none;\";class=\"" + DUMMY_CLASS_NAME +
                "\";id=\"" + createId(url) + "\";></div>'</script>";
    }

    private String injectImagePayload(URL url) {
        return "<img src=\"" + hackersHost + createId(url) + ".png\" alt=\"" + IMG_CLASS_NAME + "\";>";
    }

    private void injectPayload(URL url, String payload) {
        Set<URL> receivers = new HashSet<URL>();
        try {
            Document doc = getConnection(url).get();
            Elements forms = doc.getElementsByTag("form");
            for (Element form : forms) {
                String action = form.attr("action");
                URL receiver;
                if(action.isEmpty()) {
                    receiver = url;
                }
                else {
                    receiver = new URL(host,action);
                }
                Connection con = Jsoup.connect(receiver.toString());

                Elements inputs = form.getElementsByTag("input");
                for (Element input : inputs) {
                    if(!input.attr("name").isEmpty())
                        con.data(input.attr("name"), payload);
                }
                con.post();
                receivers.add(receiver);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private void checkForDummyInjection(){
        final String REGULAR_EXP =  "class=\"" + DUMMY_CLASS_NAME + "\";id=\"" + "(-?[0-9]+)" +  "\";";

        try {
            for(URL url : injectedIdToUrl.values()) {
                Document html = getConnection(url).get();
                Elements scripts = html.getElementsByTag("script");
                for(Element script: scripts) {
                    Pattern anchorPattern = Pattern.compile(REGULAR_EXP);
                    Matcher anchorMatcher = anchorPattern.matcher(script.toString());
                    while (anchorMatcher.find()) {
                        Integer key = new Integer(anchorMatcher.group(1));
                        if (injectedIdToUrl.containsKey(key)) {
                            dummyVulnerableUrls.add(injectedIdToUrl.get(key));
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void checkForImgInjection() {
        for(URL url : injectedIdToUrl.values()) {
            try {
                Document html = getConnection(url).get();
                Elements imgs = html.getElementsByTag("img");
                for(Element img : imgs) {
                    if(!img.attr("alt").isEmpty() && img.attr("alt").equals(IMG_CLASS_NAME)) {
                        String id = img.attr("src").replace(hackersHost, "").replace(".png", "");
                        imageVulnerableUrls.add(injectedIdToUrl.get(Integer.parseInt(id)));
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private Connection getConnection(URL url) {
        Connection connection = Jsoup.connect(url.toString());

        for (String name : cookies.keySet()) {
            connection = connection.cookie(name, cookies.get(name));
        }

        return connection;
    }

    private Integer createId(URL url) {
        return url.hashCode();
    }

    @Override
    public void pushUrl(URL url) {
        processingUrls.add(url);
    }

    @Override
    public void sendStopSignal() {
        isWorking = false;
    }
}
