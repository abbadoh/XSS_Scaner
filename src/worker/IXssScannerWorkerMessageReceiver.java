package worker;

import java.net.URL;
import java.util.Set;

public interface IXssScannerWorkerMessageReceiver {
    public void onXssScannerWorkerMessageReceived(String message);
    public void onXssScannerWorkerFinished(Set<URL> dUrls, Set<URL> iUrls);
}
