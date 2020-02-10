package com.fingerprint;

import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.biometric.engine.BiometricAuthHelper;

import androidx.appcompat.app.AppCompatActivity;

public class ActMain extends AppCompatActivity {

    private TextView tvPassword;
    private TextView tvError;
    private BiometricAuthHelper biometricAuthHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.act_main);

        tvPassword = findViewById(R.id.tvPassword);
        tvPassword.setText("abcdef");
        tvError = findViewById(R.id.tvError);

        startBiometricAuthHelper();

        Button btnSavePassword = findViewById(R.id.btnSavePassword);
        btnSavePassword.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    biometricAuthHelper.savePassword(tvPassword.getText().toString(), getAuthListener(false));
                }
            }
        });

        Button btnGetPassword = findViewById(R.id.btnGetPassword);
        btnGetPassword.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    biometricAuthHelper.getPassword(getAuthListener(true));
                }
            }
        });
    }

    // Start the finger print helper. In case this fails show error to user
    private void startBiometricAuthHelper() {
        biometricAuthHelper = new BiometricAuthHelper(this);
        if (!biometricAuthHelper.init()) {
            tvError.setText(biometricAuthHelper.getLastError());
        }
    }

    private BiometricAuthHelper.Callback getAuthListener(final boolean isGetPass) {
        return new BiometricAuthHelper.Callback() {
            @Override
            public void onSuccess(String result) {
                if (isGetPass) {
                    tvError.setText("Success!!! Pass = " + result);
                } else {
                    tvError.setText("Encrypted pass = " + result);
                }
            }

            @Override
            public void onFailure(String message) {
                tvError.setText("Failed - " + message);
            }

            @Override
            public void onError(int errorCode, String errorString) {
                tvError.setText("Error needed - " + errorString);
            }
        };
    }
}
