package worker;

import webcrawler.IWebCrawlerMessageReceiver;
import webcrawler.WebCrawler;
import xss_scanner.XssScanner;
import xss_scanner.IXssScanner;
import xss_scanner.IXssScannerMessageReceiver;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

public class XssScannerWorker implements Callable, IWebCrawlerMessageReceiver, IXssScannerMessageReceiver {
    private IXssScannerWorkerMessageReceiver receiver;
    private String url;
    Set<URL> dUrls;
    Set<URL> iUrls;
    Map<String, String> cookies;

    private IXssScanner xssScanner;

    public XssScannerWorker(IXssScannerWorkerMessageReceiver receiver, String url, Map<String, String> cookies) {
        this.receiver = receiver;
        this.url = url;
        this.cookies = cookies;
    }

    public Object call() {

        dUrls = null;
        iUrls = null;

        receiver.onXssScannerWorkerMessageReceived("Worker started");

        long startTime = System.currentTimeMillis();

        xssScanner = new XssScanner(this, url, cookies);
        Thread scannerThread = new Thread(xssScanner);
        scannerThread.start();

        try {
            WebCrawler webCrawler = new WebCrawler(this, cookies);
            URL url = new URL(this.url);

            webCrawler.addPermittedHost(url);
            webCrawler.findURLs(url);

        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        xssScanner.sendStopSignal();

        if(Thread.currentThread().isInterrupted()) {
            receiver.onXssScannerWorkerMessageReceived("Stopped");
            scannerThread.interrupt();
        } else {
            try {
                scannerThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        long totalTime = System.currentTimeMillis() - startTime;

        receiver.onXssScannerWorkerMessageReceived(String.format("Total time taken: %d s", totalTime / 1000));
        receiver.onXssScannerWorkerFinished(dUrls, iUrls);

        return null;
    }

    @Override
    public void onWebCrawlerMessageReceived(URL message) {
        receiver.onXssScannerWorkerMessageReceived(String.format("Processing url: %s",message));
        xssScanner.pushUrl(message);
    }

    @Override
    public void onScanFinished(Set<URL> vulnerableUrls, Set<URL> imageVulnerableUrls) {
        dUrls = vulnerableUrls;
        iUrls = imageVulnerableUrls;
    }
}