package xss_scanner;

import java.net.URL;
import java.util.Set;

public interface IXssScannerMessageReceiver {
    public void onScanFinished(Set<URL> DummyVulnerableUrls, Set<URL> ImageVulnerableUrls);
}
