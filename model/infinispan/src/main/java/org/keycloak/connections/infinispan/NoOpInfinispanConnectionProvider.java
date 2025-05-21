package org.keycloak.connections.infinispan;

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.util.concurrent.BlockingManager;
import org.keycloak.models.KeycloakSessionFactory; // Though not directly used, good to keep if example had it.

import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Stream;
import java.util.concurrent.CompletableFuture;


public class NoOpInfinispanConnectionProvider implements InfinispanConnectionProvider {

    private final ScheduledExecutorService scheduledExecutor = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, "noop-ispn-scheduler"));
    private final BlockingManager blockingManager = BlockingManager.create();


    public NoOpInfinispanConnectionProvider() {
        // Constructor
    }

    @Override
    public <K, V> Cache<K, V> getCache(String name, boolean createIfAbsent) {
        return null; // No actual cache
    }

    @Override
    public <K, V> RemoteCache<K, V> getRemoteCache(String name) {
        return null; // No actual remote cache
    }

    @Override
    public TopologyInfo getTopologyInfo() {
        // Returning a dummy TopologyInfo. Assuming TopologyInfo might not allow null cacheManager.
        // If TopologyInfo's constructor is more complex or needs a valid manager, this might need adjustment.
        // For a true no-op, returning null or a more minimal TopologyInfo might be better if possible.
        return new TopologyInfo(null);
    }

    @Override
    public CompletionStage<Void> migrateToProtoStream() {
        return CompletableFuture.completedFuture(null); // No migration to perform
    }
    
    @Override
    public Executor getExecutor(String name) {
        return blockingManager.asExecutor(name);
    }

    @Override
    public ScheduledExecutorService getScheduledExecutor() {
        return scheduledExecutor;
    }
    
    @Override
    public BlockingManager getBlockingManager() {
        return blockingManager;
    }

    @Override
    public void close() {
        // No-op
        scheduledExecutor.shutdownNow();
        blockingManager.stop();
    }
}
