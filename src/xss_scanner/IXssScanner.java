package xss_scanner;

import java.net.URL;

public interface IXssScanner extends Runnable{
    public void pushUrl(URL url);
    public void sendStopSignal();
}
