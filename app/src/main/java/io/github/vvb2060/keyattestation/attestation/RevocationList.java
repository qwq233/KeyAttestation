package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.util.Log;

import androidx.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {
    private static final JSONObject data = loadData();

    private static JSONObject loadData() {
        if (!isConnectedToInternet()) {
            return getJsonFromResource();
        }
        try {
            return getJsonFromUrl();
        } catch (IOException | JSONException e) {
            Log.e(AppApplication.TAG, "Error loading JSON from URL, trying local resource", e);
            return getJsonFromResource();
        }
    }

    private static JSONObject getJsonFromResource() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(AppApplication.app.getResources().openRawResource(R.raw.status)))) {
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
            Log.i(AppApplication.TAG, "Read " + stringBuilder.length() + " chars from local JSON");
            return new JSONObject(stringBuilder.toString());
        } catch (IOException | JSONException e) {
            Log.wtf(AppApplication.TAG, "Error reading local JSON", e);
            throw new RuntimeException("Unable to load JSON data", e);
        }
    }

    private static JSONObject getJsonFromUrl() throws IOException, JSONException {
        HttpURLConnection connection = getHttpURLConnection();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
            Log.i(AppApplication.TAG, "Read " + stringBuilder.length() + " chars from remote JSON");
            return new JSONObject(stringBuilder.toString());
        } finally {
            connection.disconnect();
        }
    }

    @NonNull
    private static HttpURLConnection getHttpURLConnection() throws IOException {
        URL url = new URL("https://android.googleapis.com/attestation/status");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setUseCaches(false);
        connection.setDefaultUseCaches(false);

        connection.setRequestMethod("GET");
        connection.setRequestProperty("Cache-Control", "max-age=0, no-cache, no-store, must-revalidate");
        connection.setRequestProperty("Pragma", "no-cache");
        connection.setRequestProperty("Expires", "0");

        return connection;
    }

    private static boolean isConnectedToInternet() {
        ConnectivityManager connectivityManager = (ConnectivityManager) AppApplication.app.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) return false;

        Network network = connectivityManager.getActiveNetwork();
        if (network == null) return false;

        NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);
        return capabilities != null &&
                (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
    }

    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberHex = serialNumber.toString(16).toLowerCase();
        try {
            JSONObject entries = data.getJSONObject("entries");
            JSONObject revocationEntry = entries.optJSONObject(serialNumberHex);
            if (revocationEntry != null) {
                return new RevocationList(revocationEntry.getString("status"), revocationEntry.getString("reason"));
            } else {
                Log.i(AppApplication.TAG, "Serial number '" + serialNumber + "' not found in JSON");
            }
        } catch (JSONException e) {
            Log.wtf(AppApplication.TAG, "Error parsing JSON entries", e);
            throw new RuntimeException("JSON structure unexpected", e);
        }
        return null;
    }

    @NonNull
    @Override
    public String toString() {
        return "Status: " + status + ", Reason: " + reason;
    }
}