import ddddocr
from flask import Flask, request, jsonify

app = Flask(__name__)
ocr = ddddocr.DdddOcr(show_ad=False)

@app.route('/ocr', methods=['POST'])
def ocr_capt():
    request_json = request.get_json(force=True)
    img_base64 = request_json['img_base64']
    classification = ocr.classification(img_base64.replace('data:image/png;base64,', ''))
    return jsonify({'result': classification})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
