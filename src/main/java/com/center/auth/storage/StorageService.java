package com.center.auth.storage;

import io.minio.BucketExistsArgs;
import io.minio.GetObjectArgs;
import io.minio.GetObjectResponse;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.io.InputStream;

@Service
public class StorageService {

    private final MinioClient minioClient;
    private final MinioProperties minioProperties;

    public StorageService(MinioClient minioClient, MinioProperties minioProperties) {
        this.minioClient = minioClient;
        this.minioProperties = minioProperties;
    }

    @PostConstruct
    public void ensureBucketExists() {
        try {
            boolean exists = minioClient.bucketExists(
                    BucketExistsArgs.builder().bucket(minioProperties.bucket()).build());
            if (!exists) {
                minioClient.makeBucket(MakeBucketArgs.builder().bucket(minioProperties.bucket()).build());
            }
        } catch (Exception ex) {
            throw new StorageException("Failed to initialize MinIO bucket '" + minioProperties.bucket() + "'", ex);
        }
    }

    public void upload(String objectKey, InputStream data, long size, String contentType) {
        try {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(minioProperties.bucket())
                            .object(objectKey)
                            .stream(data, size, -1L)
                            .contentType(contentType)
                            .build());
        } catch (Exception ex) {
            throw new StorageException("Failed to upload object '" + objectKey + "'", ex);
        }
    }

    public void delete(String objectKey) {
        try {
            minioClient.removeObject(
                    RemoveObjectArgs.builder().bucket(minioProperties.bucket()).object(objectKey).build());
        } catch (Exception ex) {
            throw new StorageException("Failed to delete object '" + objectKey + "'", ex);
        }
    }

    public StoredObject get(String objectKey) {
        try {
            GetObjectResponse response = minioClient.getObject(
                    GetObjectArgs.builder().bucket(minioProperties.bucket()).object(objectKey).build());
            return new StoredObject(response, response.headers().get("Content-Type"));
        } catch (Exception ex) {
            throw new StorageException("Failed to fetch object '" + objectKey + "'", ex);
        }
    }
}
