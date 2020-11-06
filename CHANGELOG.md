# pyasice Changelog

## v.1.0.1

* Reordered requests to OCSP and TSA in the `utils.finalize_signature` function.
  That was necessary for Esteid services because sometimes the signed container could not be verified,
  due to an error:
  ```
  TimeStamp time is greater than OCSP producedAt TS: 2020-11-05T15:27:59Z OCSP: 20201105152758Z
  ``` 

## v.1.0

* Initial version. Supports creating and validating XAdES signatures with Estonian ID services. 
