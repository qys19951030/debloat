import pytest
import debloat.processor as processor 
import pefile


# Can we print sizes?
def test_readable_size():
    assert processor.readable_size(10) == "10 bytes"



def test_signture_abnormality():
    # Is there information after the signature?
    # Signature is at 10 with a size of 5, total file is 15
    data_to_delete = []
    assert processor.handle_signature_abnormality(10, 5, 15, data_to_delete) == (False, 0)
    assert data_to_delete == []
    # Is there information after the signature?
    # Signature is at 10 with a size of 5, total file is 20
    data_to_delete = []
    assert processor.handle_signature_abnormality(10, 5, 20, data_to_delete) == (True, 1)
    assert data_to_delete == [(15, 20)]
    # Is the signature abnormally large?
    # Signature is at 5 with a size of 12, total file is 20
    data_to_delete = []
    assert processor.handle_signature_abnormality(5, 12, 20, data_to_delete) == (True, 17)
    assert data_to_delete == [(17, 20)]
