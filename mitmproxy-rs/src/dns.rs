use hickory_proto::op::{MessageType, Query};
use hickory_proto::rr::{Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use pyo3::{pyfunction, Python};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

fn records_to_dict<'py>(py: Python<'py>, records: &[Record]) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let mut ret: Vec<Bound<PyDict>> = Vec::with_capacity(records.len());
    for r in records {
        let record = PyDict::new_bound(py);
        record.set_item("name", r.name().to_ascii().strip_suffix('.'))?;  // FIXME suffix stripping is wrong
        record.set_item("type", u16::from(r.record_type()))?;
        record.set_item("class_", u16::from(r.dns_class()))?;
        record.set_item("ttl", r.ttl())?;
        let data = r
            .data()
            .map(|d| d.to_bytes())
            .transpose()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid record data: {}", e)))?
            .unwrap_or_default();
        record.set_item("data", PyBytes::new_bound(py, &data).unbind())?;
        ret.push(record);
    }
    Ok(ret)
}

fn queries_to_dict<'py>(py: Python<'py>, queries: &[Query]) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let mut ret: Vec<Bound<PyDict>> = Vec::with_capacity(queries.len());
    for q in queries {
        let question = PyDict::new_bound(py);
        question.set_item("name", q.name().to_ascii().strip_suffix('.'))?;  // FIXME suffix stripping is wrong
        question.set_item("type", u16::from(q.query_type()))?;
        question.set_item("class_", u16::from(q.query_class()))?;
        ret.push(question);
    }
    Ok(ret)
}

#[pyfunction]
pub fn parse_dns_message<'py>(py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyDict>> {

    let message = hickory_proto::op::Message::from_bytes(&data)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid dns message: {}", e)))?;

    let h = message.header();
    let ret = PyDict::new_bound(py);
    ret.set_item("id", h.id())?;
    ret.set_item("query", matches!(h.message_type(), MessageType::Query))?;
    ret.set_item("op_code", u8::from(h.op_code()))?;
    ret.set_item("authoritative_answer", h.authoritative())?;
    ret.set_item("truncation", h.truncated())?;
    ret.set_item("recursion_desired", h.recursion_desired())?;
    ret.set_item("recursion_available", h.recursion_available())?;
    ret.set_item("reserved", 0)?;
    ret.set_item("response_code", u16::from(h.response_code()))?;
    ret.set_item("questions", queries_to_dict(py, message.queries())?)?;
    ret.set_item("answers", records_to_dict(py, message.answers())?)?;
    ret.set_item("authorities", records_to_dict(py, message.name_servers())?)?;
    ret.set_item("additionals", records_to_dict(py, message.additionals())?)?;

    Ok(ret)
}
