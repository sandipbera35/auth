package com.center.auth.storage;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

public record StoredObject(InputStream content, String contentType) implements Closeable {

    @Override
    public void close() throws IOException {
        content.close();
    }
}
