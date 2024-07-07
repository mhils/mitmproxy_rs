use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use pyo3::{pyclass, pymethods};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

/// Incomplete: Proof-of-concept to host the entire DnsMessage class in Rust.
/// This is probably the better approach, but requires some plumbing.

#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct DnsMessage {
    inner: hickory_proto::op::Message,
}

#[pymethods]
impl DnsMessage {
    #[staticmethod]
    pub fn from_bytes(data: Vec<u8>) -> PyResult<Self> {
        let inner = hickory_proto::op::Message::from_bytes(&data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid dns message: {}", e)))?;
        Ok(Self { inner })
    }

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self
            .inner
            .to_bytes()
            .map(|b| PyBytes::new_bound(py, &b))
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid dns message: {}", e)))
    }

    pub fn get_state<'py>(&self) -> PyResult<Bound<'py, PyBytes>> {
        todo!()
    }

    pub fn set_state<'py>(&self) -> PyResult<Bound<'py, PyBytes>> {
        todo!()
    }

    pub fn copy(&self) -> Self {
        Self { inner: self.inner.clone() }
    }

    #[staticmethod]
    pub fn from_state<'py>() -> PyResult<Bound<'py, PyBytes>> {
        todo!()
    }

    pub fn to_json(&self) -> PyResult<PyDict> {
        todo!()
    }


}