import javax.swing.SwingUtilities;

public abstract class ThreadManager {

    private final Threads threadInstance;

    private static class Threads {

        private Thread thread;

        Threads(Thread thread) {
            this.thread = thread;
        }

        synchronized Thread get() {
            return thread;
        }

        synchronized void clear() {
            thread = null;
        }
    }

    private Object value;
    abstract Object construct();

    protected synchronized Object getValue() {
        return value;
    }

    private synchronized void setValue(Object value) {
        this.value = value;
    }

    public void finished() {
    }

    public void interrupt() {
        Thread thread = threadInstance.get();
        if (thread != null) {
            thread.interrupt();
        }
        threadInstance.clear();
    }

    public Object get() {
        while (true) {
            Thread thread = threadInstance.get();
            if (thread == null) {
                return getValue();
            }
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
    }

    public ThreadManager() {
        final Runnable doFinished = this::finished;

        Runnable doConstruct = new Runnable() {
            public void run() {
                try {
                    setValue(construct());
                } finally {
                    threadInstance.clear();
                }
                SwingUtilities.invokeLater(doFinished);
            }
        };
        Thread thread = new Thread(doConstruct);
        threadInstance = new Threads(thread);
    }

    public void start() {
        Thread thread = threadInstance.get();
        if (thread != null) {
            thread.start();
        }
    }
}