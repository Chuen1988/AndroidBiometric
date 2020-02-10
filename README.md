## Description
Using google androidx biometric to encrypt and decrypt plain text and store in SharedPreference

# How to use
1.  Initialize BiometricAuthHelper and perform fingerprint checking as shown below:
```
private void startBiometricAuthHelper() {
        biometricAuthHelper = new BiometricAuthHelper(this);
        if (!biometricAuthHelper.init()) {
            tvError.setText(biometricAuthHelper.getLastError());
        }
    }
```
2.  Create an Authentication callback function as shown below:
```
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
```
3.  Next, to save password (encrypt plain text and store to the Shared Preference) call the savePassword as shown below:
```
biometricAuthHelper.savePassword(tvPassword.getText().toString(), getAuthListener(false));
```
4.  To retrieve password (decrypt plain text from SharedPreference) call the getPassword as shown below:
```
biometricAuthHelper.getPassword(getAuthListener(true));
```
# Last
Sample app is provided.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
